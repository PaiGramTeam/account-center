package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"

	"paigram/internal/cache"
	"paigram/internal/model"
)

const (
	// BcryptCost is the cost factor for bcrypt hashing (better-auth recommends >= 12)
	BcryptCost = 12
	// DefaultRateLimitTimeWindow is 24 hours in milliseconds
	DefaultRateLimitTimeWindow = int64(24 * 60 * 60 * 1000)
	// DefaultRateLimitMax is 1000 requests per day
	DefaultRateLimitMax = 1000

	// botTokenStatusActive marks the current row in a token family.
	botTokenStatusActive = "active"
	// botTokenStatusRotated marks rows that were legitimately superseded by a
	// newer row in the same family via RefreshBotToken.
	botTokenStatusRotated = "rotated"
	// botTokenStatusRevoked marks rows that have been invalidated and must
	// never be honored again, e.g. after refresh-token reuse detection.
	botTokenStatusRevoked = "revoked"

	// botTokenRevokeReasonReuse is recorded on every row in a family when a
	// non-active refresh token from that family is presented again.
	botTokenRevokeReasonReuse = "token_reuse_detected"
)

// allowedRegisterBotScopes is the explicit allowlist of scopes a caller may
// request when registering a new bot through the gRPC RegisterBot RPC. Any
// scope outside this set (notably anything starting with admin.) MUST be
// rejected — see V1 hardening.
var allowedRegisterBotScopes = map[string]struct{}{
	"bot.read":  {},
	"bot.write": {},
}

// BotAuthService implements the gRPC BotAuthService
type BotAuthService struct {
	UnimplementedBotAuthServiceServer
	db                   *gorm.DB
	cache                cache.BotTokenCacheStore
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
}

// NewBotAuthService creates a new bot auth service
func NewBotAuthService(db *gorm.DB, redisClient *redis.Client, redisPrefix string) *BotAuthService {
	var tokenCache cache.BotTokenCacheStore
	if redisClient != nil {
		tokenCache = cache.NewBotTokenCache(redisClient, redisPrefix)
	}

	return &BotAuthService{
		db:                   db,
		cache:                tokenCache,
		accessTokenDuration:  time.Hour,
		refreshTokenDuration: time.Hour * 24 * 30, // 30 days
	}
}

// NewBotAuthServiceWithCache wires a BotAuthService against a caller-provided
// cache store. It exists primarily so tests can inject an in-memory fake that
// satisfies cache.BotTokenCacheStore without standing up Redis. Pass nil to
// disable caching entirely.
func NewBotAuthServiceWithCache(db *gorm.DB, store cache.BotTokenCacheStore) *BotAuthService {
	return &BotAuthService{
		db:                   db,
		cache:                store,
		accessTokenDuration:  time.Hour,
		refreshTokenDuration: time.Hour * 24 * 30,
	}
}

// RegisterBot registers a new bot client.
//
// V1 hardening:
//   - The auth interceptor now requires a valid bot access token before this
//     method runs, so the caller is always an authenticated bot.
//   - The caller may only register additional bots under the same owner user
//     they themselves belong to. Any attempt to set OwnerEmail to a different
//     user's email is rejected with PermissionDenied.
//   - Requested Scopes are validated against an explicit allowlist. Anything
//     outside that allowlist (notably admin.*) is rejected with InvalidArgument.
func (s *BotAuthService) RegisterBot(ctx context.Context, req *RegisterBotRequest) (*RegisterBotResponse, error) {
	// Validate input
	if req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "bot name is required")
	}
	if req.OwnerEmail == "" {
		return nil, status.Errorf(codes.InvalidArgument, "owner email is required")
	}

	// The auth interceptor populates ctx with the calling bot. If it isn't there
	// we treat the call as unauthenticated rather than silently fall through.
	callerBot, ok := ctx.Value("bot").(*Bot)
	if !ok || callerBot == nil || callerBot.Id == "" {
		return nil, status.Error(codes.Unauthenticated, "missing authenticated caller")
	}

	// Resolve the caller's owner user via the bot row, then take that user's
	// primary email as the canonical caller identity. We do not trust any
	// owner-email field on the proto Bot — there isn't one — and we do not
	// trust the request body to assert who the caller is.
	var callerBotRow model.Bot
	if err := s.db.Where("id = ?", callerBot.Id).First(&callerBotRow).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.Unauthenticated, "caller bot not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to resolve caller bot: %v", err)
	}

	var callerEmail model.UserEmail
	if err := s.db.Where("user_id = ? AND is_primary = ?", callerBotRow.OwnerUserID, true).First(&callerEmail).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Fall back to any email so we still have a basis for comparison.
			if fbErr := s.db.Where("user_id = ?", callerBotRow.OwnerUserID).First(&callerEmail).Error; fbErr != nil {
				return nil, status.Error(codes.PermissionDenied, "caller has no resolvable email")
			}
		} else {
			return nil, status.Errorf(codes.Internal, "failed to resolve caller email: %v", err)
		}
	}

	// Owner-email enforcement (case-insensitive). Reject any cross-user attempt.
	if !strings.EqualFold(strings.TrimSpace(req.OwnerEmail), strings.TrimSpace(callerEmail.Email)) {
		return nil, status.Error(codes.PermissionDenied, "owner_email must match the authenticated caller")
	}

	// Scope allowlist. Reject anything outside { bot.read, bot.write }.
	for _, requested := range req.Scopes {
		scope := strings.TrimSpace(requested)
		if scope == "" {
			continue
		}
		if _, ok := allowedRegisterBotScopes[scope]; !ok {
			return nil, status.Errorf(codes.InvalidArgument, "scope %q is not permitted via RegisterBot", scope)
		}
	}

	// Find owner user by the validated email. We re-query so the persisted
	// OwnerUserID is consistent with what's actually in the DB right now.
	var userEmail model.UserEmail
	if err := s.db.Where("email = ?", req.OwnerEmail).First(&userEmail).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(codes.NotFound, "owner user not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to find owner: %v", err)
	}

	// Generate bot credentials
	botID := uuid.New().String()
	apiKey := s.generateAPIKey()
	apiSecret := s.generateAPISecret()

	// Hash the API secret with higher cost for better security
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(apiSecret), BcryptCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to hash secret: %v", err)
	}

	// Create bot. Default empty metadata to "{}" so the JSON column constraint
	// is always satisfied — RegisterBot used to crash with a CONSTRAINT error
	// when the caller didn't supply any metadata.
	metadata := strings.TrimSpace(req.Metadata)
	if metadata == "" {
		metadata = "{}"
	}
	bot := &model.Bot{
		ID:          botID,
		Name:        req.Name,
		Description: req.Description,
		Type:        s.convertBotTypeToString(req.Type),
		Status:      "ACTIVE",
		OwnerUserID: userEmail.UserID,
		APIKey:      apiKey,
		APISecret:   string(hashedSecret),
		Scopes:      s.encodeScopesJSON(req.Scopes),
		Metadata:    metadata,
	}

	if err := s.db.Create(bot).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create bot: %v", err)
	}

	return &RegisterBotResponse{
		Bot:       s.modelBotToProto(bot),
		ApiKey:    apiKey,
		ApiSecret: apiSecret, // Return unhashed secret only during registration
	}, nil
}

// BotLogin authenticates a bot and returns access tokens
func (s *BotAuthService) BotLogin(ctx context.Context, req *BotLoginRequest) (*BotLoginResponse, error) {
	// Validate input
	if req.ApiKey == "" || req.ApiSecret == "" {
		return nil, status.Errorf(codes.InvalidArgument, "api key and secret are required")
	}

	// Find bot by API key
	var bot model.Bot
	if err := s.db.Where("api_key = ?", req.ApiKey).First(&bot).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
		}
		return nil, status.Errorf(codes.Internal, "failed to find bot: %v", err)
	}

	// Verify API secret
	if err := bcrypt.CompareHashAndPassword([]byte(bot.APISecret), []byte(req.ApiSecret)); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	// Check bot status
	if bot.Status != "ACTIVE" {
		return nil, status.Errorf(codes.PermissionDenied, "bot is not active")
	}

	// Generate tokens (plaintext - will be hashed before storage)
	accessToken := s.generateToken()
	refreshToken := s.generateToken()

	// Hash tokens for secure storage
	accessTokenHash := hashToken(accessToken)
	refreshTokenHash := hashToken(refreshToken)

	// Create token record with default rate limiting
	rateLimitTimeWindow := DefaultRateLimitTimeWindow
	rateLimitMax := DefaultRateLimitMax

	// Each fresh login starts a brand-new token family. Subsequent rotations
	// performed by RefreshBotToken stay in the same family so reuse detection
	// can revoke them all at once.
	familyID := uuid.New().String()

	botToken := &model.BotToken{
		BotID:               bot.ID,
		AccessTokenHash:     accessTokenHash,
		RefreshTokenHash:    refreshTokenHash,
		RateLimitEnabled:    true,
		RateLimitTimeWindow: &rateLimitTimeWindow,
		RateLimitMax:        &rateLimitMax,
		RequestCount:        0,
		Metadata:            "{}",
		ExpiresAt:           time.Now().Add(s.accessTokenDuration),
		FamilyID:            familyID,
		Status:              botTokenStatusActive,
	}

	if err := s.db.Create(botToken).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create token: %v", err)
	}

	// Update last active time
	s.db.Model(&bot).Update("last_active_at", time.Now())

	return &BotLoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.accessTokenDuration.Seconds()),
		TokenType:    "Bearer",
		Bot:          s.modelBotToProto(&bot),
	}, nil
}

// RefreshBotToken refreshes an access token using a refresh token.
//
// V11 hardening — token-family rotation with reuse detection:
//   - The presented refresh token is hashed and looked up. If no row matches at
//     all, we return Unauthenticated (the token never existed or its row was
//     hard-deleted).
//   - If a row matches but its status is no longer 'active', the token has
//     already been rotated or revoked. Any subsequent presentation must be
//     treated as a reuse attack: we revoke every row in the same family and
//     return Unauthenticated. The rest of the family stops being honored.
//   - On the happy path, the matching row is marked 'rotated' and a brand-new
//     row is inserted in the same family with status 'active' and freshly
//     generated access/refresh hashes. The plaintext tokens are returned to
//     the caller; old tokens are no longer valid.
func (s *BotAuthService) RefreshBotToken(ctx context.Context, req *RefreshBotTokenRequest) (*RefreshBotTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Errorf(codes.InvalidArgument, "refresh token is required")
	}

	refreshTokenHash := hashToken(req.RefreshToken)

	// Find the row that minted this refresh token. We deliberately do NOT
	// filter on revoked_at IS NULL or status='active' here — we need to *see*
	// non-active rows so reuse detection can fire.
	var botToken model.BotToken
	if err := s.db.Preload("Bot").Where("refresh_token_hash = ?", refreshTokenHash).First(&botToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(codes.Unauthenticated, "invalid refresh token")
		}
		return nil, status.Errorf(codes.Internal, "failed to find token: %v", err)
	}

	// Reuse detection: any presentation of a non-active row's refresh token is
	// a security violation. Revoke the whole family.
	if botToken.Status != botTokenStatusActive {
		now := time.Now()
		log.Printf("[security] bot token reuse detected family=%s bot=%s row_id=%d row_status=%s", botToken.FamilyID, botToken.BotID, botToken.ID, botToken.Status)

		// Snapshot every row in the family BEFORE we update them so we can
		// invalidate each row's cache entry — including the still-active row,
		// whose plaintext access token is in the attacker's hands. Without
		// this step ValidateBotToken would keep honoring that access token
		// from the cache fast path until natural TTL.
		var familyRows []model.BotToken
		if err := s.db.Where("family_id = ?", botToken.FamilyID).Find(&familyRows).Error; err != nil {
			log.Printf("[security] failed to enumerate bot token family %s for cache invalidation: %v", botToken.FamilyID, err)
			// Continue: DB-side revocation below is still the source of truth
			// on cache miss; we just lose the fast-path cache invalidation.
		}

		// Best-effort revoke; even if this errors we still refuse the caller.
		if err := s.db.Model(&model.BotToken{}).
			Where("family_id = ?", botToken.FamilyID).
			Updates(map[string]any{
				"status":         botTokenStatusRevoked,
				"revoked_at":     now,
				"revoked_reason": botTokenRevokeReasonReuse,
			}).Error; err != nil {
			log.Printf("[security] failed to revoke bot token family %s after reuse detection: %v", botToken.FamilyID, err)
		}

		// Invalidate the cache for every member of the now-revoked family,
		// not just the row whose refresh token tripped the detection. Each
		// call is fire-and-forget but logs on error so an operator can spot
		// cache outages during a security event.
		s.invalidateAccessTokenCache(familyRows)

		return nil, status.Errorf(codes.Unauthenticated, "invalid refresh token")
	}

	// Check bot status
	if botToken.Bot.Status != "ACTIVE" {
		return nil, status.Errorf(codes.PermissionDenied, "bot is not active")
	}

	// Generate new tokens (token rotation for security)
	newAccessToken := s.generateToken()
	newRefreshToken := s.generateToken()
	newAccessTokenHash := hashToken(newAccessToken)
	newRefreshTokenHash := hashToken(newRefreshToken)

	now := time.Now()
	newExpiresAt := now.Add(s.accessTokenDuration)
	rateLimitTimeWindow := DefaultRateLimitTimeWindow
	rateLimitMax := DefaultRateLimitMax

	// Atomically mark the current row 'rotated' and insert the successor.
	// If anything in the transaction fails, both sides revert and the caller's
	// existing tokens stay valid.
	newRow := model.BotToken{
		BotID:               botToken.BotID,
		AccessTokenHash:     newAccessTokenHash,
		RefreshTokenHash:    newRefreshTokenHash,
		RateLimitEnabled:    true,
		RateLimitTimeWindow: &rateLimitTimeWindow,
		RateLimitMax:        &rateLimitMax,
		RequestCount:        0,
		Metadata:            "{}",
		ExpiresAt:           newExpiresAt,
		FamilyID:            botToken.FamilyID,
		Status:              botTokenStatusActive,
	}

	if err := s.db.Transaction(func(tx *gorm.DB) error {
		// Concurrency guard: only flip the row if it is still 'active'. If a
		// concurrent reuse detection beat us to it, RowsAffected will be 0
		// and we abort the rotation.
		res := tx.Model(&model.BotToken{}).
			Where("id = ? AND status = ?", botToken.ID, botTokenStatusActive).
			Updates(map[string]any{"status": botTokenStatusRotated})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return errors.New("token row no longer active")
		}
		return tx.Create(&newRow).Error
	}); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid refresh token")
	}

	// Best-effort cache invalidation of the previous access token hash so a
	// cached validation can't outlive its rotation. Errors are logged inside
	// the helper.
	s.invalidateAccessTokenCache([]model.BotToken{botToken})

	// Update last active time
	s.db.Model(&botToken.Bot).Update("last_active_at", now)

	return &RefreshBotTokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(s.accessTokenDuration.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// ValidateBotToken validates an access token with rate limiting and caching
func (s *BotAuthService) ValidateBotToken(ctx context.Context, req *ValidateBotTokenRequest) (*ValidateBotTokenResponse, error) {
	if req.AccessToken == "" {
		return nil, status.Errorf(codes.InvalidArgument, "access token is required")
	}

	// Hash the access token to look up in database/cache
	accessTokenHash := hashToken(req.AccessToken)

	// Check revocation cache first (fastest path)
	if s.cache != nil {
		revoked, err := s.cache.IsRevoked(ctx, accessTokenHash)
		if err == nil && revoked {
			return &ValidateBotTokenResponse{Valid: false}, nil
		}
	}

	// Try to get from cache (fast path - no DB query!)
	if s.cache != nil {
		cacheData, err := s.cache.Get(ctx, accessTokenHash)
		if err == nil && cacheData != nil {
			// Cache hit! Validate using cached data
			now := time.Now()

			// Check expiry from cache
			if now.After(cacheData.ExpiresAt) {
				return &ValidateBotTokenResponse{Valid: false}, nil
			}

			// Check bot status from cache
			if cacheData.BotStatus != "ACTIVE" {
				return &ValidateBotTokenResponse{Valid: false}, nil
			}

			// Check rate limit from cache
			if cacheData.RateLimitEnabled && cacheData.RateLimitTimeWindow != nil && cacheData.RateLimitMax != nil {
				timeWindow := time.Duration(*cacheData.RateLimitTimeWindow) * time.Millisecond

				needsUpdate := false
				if cacheData.LastRequest != nil {
					timeSinceLastRequest := now.Sub(*cacheData.LastRequest)

					if timeSinceLastRequest > timeWindow {
						// Reset window
						cacheData.RequestCount = 1
						cacheData.LastRequest = &now
						needsUpdate = true
					} else {
						// Within window - check limit
						if cacheData.RequestCount >= *cacheData.RateLimitMax {
							tryAgainIn := timeWindow - timeSinceLastRequest
							return &ValidateBotTokenResponse{
								Valid:      false,
								Error:      "RATE_LIMITED",
								TryAgainIn: int64(tryAgainIn / time.Millisecond),
							}, nil
						}
						cacheData.RequestCount++
						needsUpdate = true
					}
				} else {
					// First request
					cacheData.RequestCount = 1
					cacheData.LastRequest = &now
					needsUpdate = true
				}

				// Update cache with new rate limit counters (async)
				if needsUpdate {
					go s.cache.UpdateRateLimit(context.Background(), accessTokenHash, cacheData.RequestCount, *cacheData.LastRequest)
				}
			}

			// Verify required permissions from cached scopes
			permissionsGranted := true
			if len(req.RequiredPermissions) > 0 {
				permissionsGranted = s.verifyPermissions(cacheData.Scopes, req.RequiredPermissions)
				if !permissionsGranted {
					return &ValidateBotTokenResponse{
						Valid:              false,
						Error:              "INSUFFICIENT_PERMISSIONS",
						PermissionsGranted: false,
					}, nil
				}
			}

			// Cache validation successful
			return &ValidateBotTokenResponse{
				Valid: true,
				Bot: &Bot{
					Id:     cacheData.BotID,
					Name:   cacheData.BotName,
					Status: s.convertStringToBotStatus(cacheData.BotStatus),
					Scopes: cacheData.Scopes,
				},
				Scopes:             cacheData.Scopes,
				ExpiresAt:          timestamppb.New(cacheData.ExpiresAt),
				PermissionsGranted: permissionsGranted,
			}, nil
		}
	}

	// Cache miss - fall back to database lookup. We only honor rows whose
	// lifecycle status is still 'active' so that rotated/revoked rows can
	// never be replayed even if their original expires_at is still in the
	// future.
	var botToken model.BotToken
	if err := s.db.Preload("Bot").Where("access_token_hash = ? AND revoked_at IS NULL AND status = ?", accessTokenHash, botTokenStatusActive).First(&botToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &ValidateBotTokenResponse{Valid: false}, nil
		}
		return nil, status.Errorf(codes.Internal, "failed to find token: %v", err)
	}

	// Check if token is expired
	now := time.Now()
	if now.After(botToken.ExpiresAt) {
		return &ValidateBotTokenResponse{Valid: false}, nil
	}

	// Check bot status
	if botToken.Bot.Status != "ACTIVE" {
		return &ValidateBotTokenResponse{Valid: false}, nil
	}

	// Check rate limit (sliding window algorithm)
	if botToken.RateLimitEnabled && botToken.RateLimitTimeWindow != nil && botToken.RateLimitMax != nil {
		timeWindow := time.Duration(*botToken.RateLimitTimeWindow) * time.Millisecond

		// Check if we need to reset the window
		if botToken.LastRequest.Valid {
			timeSinceLastRequest := now.Sub(botToken.LastRequest.Time)

			if timeSinceLastRequest > timeWindow {
				// Reset window
				botToken.RequestCount = 1
				botToken.LastRequest.Time = now
				botToken.LastRequest.Valid = true
			} else {
				// Within window - check limit
				if botToken.RequestCount >= *botToken.RateLimitMax {
					// Rate limit exceeded
					tryAgainIn := timeWindow - timeSinceLastRequest
					return &ValidateBotTokenResponse{
						Valid:      false,
						Error:      "RATE_LIMITED",
						TryAgainIn: int64(tryAgainIn / time.Millisecond),
					}, nil
				}
				// Increment counter
				botToken.RequestCount++
			}
		} else {
			// First request
			botToken.RequestCount = 1
			botToken.LastRequest.Time = now
			botToken.LastRequest.Valid = true
		}

		// Update rate limit counters in database (async to avoid blocking)
		go func() {
			if err := s.db.Model(&botToken).Updates(map[string]interface{}{
				"request_count": botToken.RequestCount,
				"last_request":  botToken.LastRequest,
			}).Error; err != nil {
				// Log error but don't fail validation
			}
		}()
	}

	// Parse scopes
	scopes := s.decodeScopesJSON(botToken.Bot.Scopes)

	// Verify required permissions (if provided)
	permissionsGranted := true
	if len(req.RequiredPermissions) > 0 {
		permissionsGranted = s.verifyPermissions(scopes, req.RequiredPermissions)
		if !permissionsGranted {
			return &ValidateBotTokenResponse{
				Valid:              false,
				Error:              "INSUFFICIENT_PERMISSIONS",
				PermissionsGranted: false,
			}, nil
		}
	}

	// Cache the validation result for future requests
	if s.cache != nil {
		var lastRequest *time.Time
		if botToken.LastRequest.Valid {
			lastRequest = &botToken.LastRequest.Time
		}

		cacheData := &cache.BotTokenCacheData{
			Valid:               true,
			BotID:               botToken.Bot.ID,
			BotName:             botToken.Bot.Name,
			BotStatus:           botToken.Bot.Status,
			Scopes:              scopes,
			ExpiresAt:           botToken.ExpiresAt,
			RateLimitEnabled:    botToken.RateLimitEnabled,
			RateLimitTimeWindow: botToken.RateLimitTimeWindow,
			RateLimitMax:        botToken.RateLimitMax,
			RequestCount:        botToken.RequestCount,
			LastRequest:         lastRequest,
		}

		// Cache asynchronously (don't block response)
		go s.cache.Set(context.Background(), accessTokenHash, cacheData)
	}

	return &ValidateBotTokenResponse{
		Valid:              true,
		Bot:                s.modelBotToProto(&botToken.Bot),
		Scopes:             scopes,
		ExpiresAt:          timestamppb.New(botToken.ExpiresAt),
		PermissionsGranted: permissionsGranted,
	}, nil
}

// RevokeBotToken revokes an access token and clears cache
func (s *BotAuthService) RevokeBotToken(ctx context.Context, req *RevokeBotTokenRequest) (*RevokeBotTokenResponse, error) {
	if req.AccessToken == "" {
		return nil, status.Errorf(codes.InvalidArgument, "access token is required")
	}

	// Hash the access token to look up in database
	accessTokenHash := hashToken(req.AccessToken)

	// Get token to find expiry time for cache TTL
	var botToken model.BotToken
	if err := s.db.Where("access_token_hash = ? AND revoked_at IS NULL", accessTokenHash).First(&botToken).Error; err == nil {
		s.invalidateAccessTokenCache([]model.BotToken{botToken})
	}

	// Find and revoke token in database
	result := s.db.Model(&model.BotToken{}).
		Where("access_token_hash = ? AND revoked_at IS NULL", accessTokenHash).
		Update("revoked_at", time.Now())

	if result.Error != nil {
		return nil, status.Errorf(codes.Internal, "failed to revoke token: %v", result.Error)
	}

	if result.RowsAffected == 0 {
		return &RevokeBotTokenResponse{
			Success: false,
			Message: "token not found or already revoked",
		}, nil
	}

	return &RevokeBotTokenResponse{
		Success: true,
		Message: "token revoked successfully",
	}, nil
}

// GetBotInfo retrieves bot information
func (s *BotAuthService) GetBotInfo(ctx context.Context, req *GetBotInfoRequest) (*GetBotInfoResponse, error) {
	if req.BotId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "bot id is required")
	}

	var bot model.Bot
	if err := s.db.First(&bot, "id = ?", req.BotId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(codes.NotFound, "bot not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to get bot: %v", err)
	}

	return &GetBotInfoResponse{
		Bot: s.modelBotToProto(&bot),
	}, nil
}

// Helper functions

// invalidateAccessTokenCache fires best-effort cache invalidations for every
// row whose access-token hash should no longer be honored — typically the
// row(s) involved in a rotation or family-wide revocation.
//
// It writes to two cache namespaces per row:
//
//   - MarkRevoked: adds the hash to a tombstone set so the IsRevoked fast path
//     in ValidateBotToken short-circuits even if a positive cache entry hasn't
//     yet been evicted.
//   - Delete: removes any positive cache entry so a stale Get() can't keep
//     returning Valid:true until natural TTL.
//
// Each invalidation runs in its own goroutine and logs on error rather than
// silently dropping the failure: during a security-relevant revocation the
// operator must see whether cache invalidation actually landed.
func (s *BotAuthService) invalidateAccessTokenCache(rows []model.BotToken) {
	if s.cache == nil {
		return
	}
	for _, row := range rows {
		row := row // capture
		if row.AccessTokenHash == "" {
			continue
		}
		go func() {
			if err := s.cache.MarkRevoked(context.Background(), row.AccessTokenHash, row.ExpiresAt); err != nil {
				log.Printf("[security] failed to mark bot token revoked in cache bot=%s row_id=%d: %v", row.BotID, row.ID, err)
			}
		}()
		go func() {
			if err := s.cache.Delete(context.Background(), row.AccessTokenHash); err != nil {
				log.Printf("[security] failed to delete bot token cache entry bot=%s row_id=%d: %v", row.BotID, row.ID, err)
			}
		}()
	}
}

// hashToken creates SHA-256 hash of token for secure database storage
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (s *BotAuthService) generateAPIKey() string {
	return "pk_" + s.generateRandomString(48) // 64 chars base64
}

func (s *BotAuthService) generateAPISecret() string {
	return "sk_" + s.generateRandomString(48) // 64 chars base64
}

func (s *BotAuthService) generateToken() string {
	return s.generateRandomString(48) // 64 chars base64
}

// generateRandomString generates a cryptographically secure random string
// Fixed: No longer truncates base64 output, preserving full entropy
func (s *BotAuthService) generateRandomString(byteLength int) string {
	bytes := make([]byte, byteLength)
	if _, err := rand.Read(bytes); err != nil {
		// In production, this should be logged and handled properly
		panic("failed to generate random bytes: " + err.Error())
	}
	// Return full base64 string without truncation (preserves all entropy)
	return base64.URLEncoding.EncodeToString(bytes)
}

func (s *BotAuthService) encodeScopesJSON(scopes []string) string {
	if len(scopes) == 0 {
		return "[]"
	}
	data, _ := json.Marshal(scopes)
	return string(data)
}

func (s *BotAuthService) decodeScopesJSON(scopesJSON string) []string {
	var scopes []string
	json.Unmarshal([]byte(scopesJSON), &scopes)
	return scopes
}

// verifyPermissions checks if granted scopes satisfy required permissions
// Scopes format: ["resource:action", "files:read", "files:write", "users:read"]
// Required permissions format: map[resource][]actions
func (s *BotAuthService) verifyPermissions(grantedScopes []string, requiredPerms map[string]*PermissionActions) bool {
	// Convert scopes to permissions map
	grantedPerms := make(map[string]map[string]bool)
	for _, scope := range grantedScopes {
		parts := strings.Split(scope, ":")
		if len(parts) == 2 {
			resource := parts[0]
			action := parts[1]
			if grantedPerms[resource] == nil {
				grantedPerms[resource] = make(map[string]bool)
			}
			grantedPerms[resource][action] = true
		}
	}

	// Check all required permissions
	for resource, permActions := range requiredPerms {
		granted, ok := grantedPerms[resource]
		if !ok {
			// Resource not granted at all
			return false
		}
		for _, action := range permActions.Actions {
			if !granted[action] {
				// Required action not granted
				return false
			}
		}
	}

	return true
}

func (s *BotAuthService) modelBotToProto(bot *model.Bot) *Bot {
	protoBot := &Bot{
		Id:          bot.ID,
		Name:        bot.Name,
		Description: bot.Description,
		Type:        s.convertStringToBotType(bot.Type),
		Status:      s.convertStringToBotStatus(bot.Status),
		Scopes:      s.decodeScopesJSON(bot.Scopes),
		Metadata:    bot.Metadata,
		CreatedAt:   timestamppb.New(bot.CreatedAt),
		UpdatedAt:   timestamppb.New(bot.UpdatedAt),
	}

	if bot.LastActiveAt.Valid {
		protoBot.LastActiveAt = timestamppb.New(bot.LastActiveAt.Time)
	}

	return protoBot
}

func (s *BotAuthService) convertBotTypeToString(botType BotType) string {
	switch botType {
	case BotType_BOT_TYPE_TELEGRAM:
		return "TELEGRAM"
	case BotType_BOT_TYPE_DISCORD:
		return "DISCORD"
	case BotType_BOT_TYPE_QQ:
		return "QQ"
	case BotType_BOT_TYPE_WECHAT:
		return "WECHAT"
	default:
		return "OTHER"
	}
}

func (s *BotAuthService) convertStringToBotType(typeStr string) BotType {
	switch strings.ToUpper(typeStr) {
	case "TELEGRAM":
		return BotType_BOT_TYPE_TELEGRAM
	case "DISCORD":
		return BotType_BOT_TYPE_DISCORD
	case "QQ":
		return BotType_BOT_TYPE_QQ
	case "WECHAT":
		return BotType_BOT_TYPE_WECHAT
	default:
		return BotType_BOT_TYPE_OTHER
	}
}

func (s *BotAuthService) convertStringToBotStatus(status string) BotStatus {
	switch strings.ToUpper(status) {
	case "ACTIVE":
		return BotStatus_BOT_STATUS_ACTIVE
	case "INACTIVE":
		return BotStatus_BOT_STATUS_INACTIVE
	case "SUSPENDED":
		return BotStatus_BOT_STATUS_SUSPENDED
	case "REVOKED":
		return BotStatus_BOT_STATUS_REVOKED
	default:
		return BotStatus_BOT_STATUS_UNSPECIFIED
	}
}

// Note: These types would normally be generated from the proto files
// For now, we'll define minimal interfaces

type UnimplementedBotAuthServiceServer struct{}

type RegisterBotRequest struct {
	Name        string
	Description string
	Type        BotType
	Scopes      []string
	OwnerEmail  string
	Metadata    string // JSON string
}

type RegisterBotResponse struct {
	Bot       *Bot
	ApiKey    string
	ApiSecret string
}

type BotLoginRequest struct {
	ApiKey    string
	ApiSecret string
}

type BotLoginResponse struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	TokenType    string
	Bot          *Bot
}

type RefreshBotTokenRequest struct {
	RefreshToken string
}

type RefreshBotTokenResponse struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	TokenType    string
}

type ValidateBotTokenRequest struct {
	AccessToken         string
	RequiredPermissions map[string]*PermissionActions // Optional: permissions to verify
}

type ValidateBotTokenResponse struct {
	Valid              bool
	Bot                *Bot
	Scopes             []string
	ExpiresAt          *timestamppb.Timestamp
	Error              string // Error code for rate limiting or other issues
	TryAgainIn         int64  // Milliseconds to wait before retry (for rate limiting)
	PermissionsGranted bool   // Whether required permissions are granted
}

// PermissionActions represents a list of actions for a resource
type PermissionActions struct {
	Actions []string
}

type RevokeBotTokenRequest struct {
	AccessToken string
}

type RevokeBotTokenResponse struct {
	Success bool
	Message string
}

type GetBotInfoRequest struct {
	BotId string
}

type GetBotInfoResponse struct {
	Bot *Bot
}

type Bot struct {
	Id           string
	Name         string
	Description  string
	Type         BotType
	Status       BotStatus
	Scopes       []string
	Metadata     string // JSON string
	CreatedAt    *timestamppb.Timestamp
	UpdatedAt    *timestamppb.Timestamp
	LastActiveAt *timestamppb.Timestamp
}

type BotType int32

const (
	BotType_BOT_TYPE_UNSPECIFIED BotType = 0
	BotType_BOT_TYPE_TELEGRAM    BotType = 1
	BotType_BOT_TYPE_DISCORD     BotType = 2
	BotType_BOT_TYPE_QQ          BotType = 3
	BotType_BOT_TYPE_WECHAT      BotType = 4
	BotType_BOT_TYPE_OTHER       BotType = 99
)

type BotStatus int32

const (
	BotStatus_BOT_STATUS_UNSPECIFIED BotStatus = 0
	BotStatus_BOT_STATUS_ACTIVE      BotStatus = 1
	BotStatus_BOT_STATUS_INACTIVE    BotStatus = 2
	BotStatus_BOT_STATUS_SUSPENDED   BotStatus = 3
	BotStatus_BOT_STATUS_REVOKED     BotStatus = 4
)

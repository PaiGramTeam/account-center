package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
)

// BotAuthService implements the gRPC BotAuthService
type BotAuthService struct {
	UnimplementedBotAuthServiceServer
	db                   *gorm.DB
	cache                *cache.BotTokenCache
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
}

// NewBotAuthService creates a new bot auth service
func NewBotAuthService(db *gorm.DB, redisClient *redis.Client, redisPrefix string) *BotAuthService {
	var tokenCache *cache.BotTokenCache
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

// RegisterBot registers a new bot client
func (s *BotAuthService) RegisterBot(ctx context.Context, req *RegisterBotRequest) (*RegisterBotResponse, error) {
	// Validate input
	if req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "bot name is required")
	}
	if req.OwnerEmail == "" {
		return nil, status.Errorf(codes.InvalidArgument, "owner email is required")
	}

	// Find owner user
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

	// Create bot
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
		Metadata:    req.Metadata, // Store metadata as-is (should be valid JSON)
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

	botToken := &model.BotToken{
		BotID:               bot.ID,
		AccessTokenHash:     accessTokenHash,
		RefreshTokenHash:    refreshTokenHash,
		RateLimitEnabled:    true,
		RateLimitTimeWindow: &rateLimitTimeWindow,
		RateLimitMax:        &rateLimitMax,
		RequestCount:        0,
		ExpiresAt:           time.Now().Add(s.accessTokenDuration),
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

// RefreshBotToken refreshes an access token using a refresh token
func (s *BotAuthService) RefreshBotToken(ctx context.Context, req *RefreshBotTokenRequest) (*RefreshBotTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Errorf(codes.InvalidArgument, "refresh token is required")
	}

	// Hash the refresh token to look up in database
	refreshTokenHash := hashToken(req.RefreshToken)

	// Find token record
	var botToken model.BotToken
	if err := s.db.Preload("Bot").Where("refresh_token_hash = ? AND revoked_at IS NULL", refreshTokenHash).First(&botToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Potential refresh token reuse attack detected
			// In production, you may want to revoke all tokens for this bot
			return nil, status.Errorf(codes.Unauthenticated, "invalid refresh token")
		}
		return nil, status.Errorf(codes.Internal, "failed to find token: %v", err)
	}

	// Check bot status
	if botToken.Bot.Status != "ACTIVE" {
		return nil, status.Errorf(codes.PermissionDenied, "bot is not active")
	}

	// Generate new tokens (token rotation for security)
	newAccessToken := s.generateToken()
	newRefreshToken := s.generateToken()

	// Hash new tokens
	newAccessTokenHash := hashToken(newAccessToken)
	newRefreshTokenHash := hashToken(newRefreshToken)

	// Update token record with new hashes
	botToken.AccessTokenHash = newAccessTokenHash
	botToken.RefreshTokenHash = newRefreshTokenHash
	botToken.ExpiresAt = time.Now().Add(s.accessTokenDuration)

	if err := s.db.Save(&botToken).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update token: %v", err)
	}

	// Update last active time
	s.db.Model(&botToken.Bot).Update("last_active_at", time.Now())

	return &RefreshBotTokenResponse{
		AccessToken:  newAccessToken,  // Return plaintext token to client
		RefreshToken: newRefreshToken, // Return plaintext token to client
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

	// Cache miss - fall back to database lookup
	var botToken model.BotToken
	if err := s.db.Preload("Bot").Where("access_token_hash = ? AND revoked_at IS NULL", accessTokenHash).First(&botToken).Error; err != nil {
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
		// Mark as revoked in cache
		if s.cache != nil {
			go s.cache.MarkRevoked(context.Background(), accessTokenHash, botToken.ExpiresAt)
			go s.cache.Delete(context.Background(), accessTokenHash)
		}
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

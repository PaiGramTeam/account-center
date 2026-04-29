package auth

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"paigram/internal/config"
	"paigram/internal/handler/shared"
	"paigram/internal/middleware"
	"paigram/internal/model"
	"paigram/internal/oidc"
	"paigram/internal/response"
	"paigram/internal/service"
	piiutil "paigram/internal/utils/pii"
	"paigram/internal/utils/secsubtle"
)

var (
	telegramOIDCIssuer        = "https://oauth.telegram.org"
	telegramOIDCJWKSURL       = "https://oauth.telegram.org/.well-known/jwks.json"
	errProviderAlreadyBound   = errors.New("provider already bound to another user")
	errProviderRebindConflict = errors.New("provider already bound to a different account on this user")
	errMissingBindUser        = errors.New("missing oauth bind user")
	errBindAuthRequired       = errors.New("bind callback requires authenticated user")
	errBindUserMismatch       = errors.New("bind callback authenticated user mismatch")
)

// knownOIDCProviderDefaults supplies issuer + JWKS URL fall-backs for
// well-known OIDC providers when the operator did not configure them
// explicitly. We deliberately do not include Telegram here — Telegram's
// flow runs through verifyTelegramIDToken (separate path).
//
// These values are intentionally hard-coded rather than discovered via
// /.well-known/openid-configuration so a misconfigured DNS / proxy cannot
// silently steer verification to an attacker-controlled server.
var knownOIDCProviderDefaults = map[string]struct {
	Issuer  string
	JWKSURL string
}{
	"google": {
		Issuer:  "https://accounts.google.com",
		JWKSURL: "https://www.googleapis.com/oauth2/v3/certs",
	},
	"microsoft": {
		Issuer:  "https://login.microsoftonline.com/common/v2.0",
		JWKSURL: "https://login.microsoftonline.com/common/discovery/v2.0/keys",
	},
}

// oidcVerifierCache lazily builds and caches an *oidc.Verifier per provider
// name. Verifiers themselves cache JWKS internally, so this map exists only
// to avoid allocating a new verifier (and its underlying JWKS cache) on
// every callback. It is safe for concurrent use.
type oidcVerifierCache struct {
	mu        sync.Mutex
	verifiers map[string]*oidc.Verifier
}

func newOIDCVerifierCache() *oidcVerifierCache {
	return &oidcVerifierCache{verifiers: map[string]*oidc.Verifier{}}
}

// verifierFor returns a verifier for the given provider, building it lazily.
// Returns an error if the provider has insufficient configuration to verify
// id_tokens (issuer/jwks/audience all required). The error is intentionally
// returned rather than nil + skip — V3 fails closed.
func (c *oidcVerifierCache) verifierFor(provider string, providerCfg config.OAuthProviderConfig) (*oidc.Verifier, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if v, ok := c.verifiers[provider]; ok {
		return v, nil
	}

	issuer := strings.TrimSpace(providerCfg.Issuer)
	jwksURL := strings.TrimSpace(providerCfg.JWKSURL)
	if defaults, ok := knownOIDCProviderDefaults[strings.ToLower(provider)]; ok {
		if issuer == "" {
			issuer = defaults.Issuer
		}
		if jwksURL == "" {
			jwksURL = defaults.JWKSURL
		}
	}
	audience := strings.TrimSpace(providerCfg.ClientID)

	if issuer == "" || jwksURL == "" || audience == "" {
		return nil, fmt.Errorf(
			"oidc verifier not configured for provider %q: issuer=%q jwks_url=%q client_id_set=%t",
			provider, issuer, jwksURL, audience != "",
		)
	}

	v, err := oidc.NewVerifier(oidc.Config{
		Issuer:   issuer,
		Audience: audience,
		JWKSURL:  jwksURL,
	})
	if err != nil {
		return nil, err
	}

	c.verifiers[provider] = v
	return v, nil
}

type initiateOAuthRequest struct {
	RedirectTo string `json:"redirect_to"`
}

// swagger:route POST /api/v1/auth/oauth/{provider}/init auth initiateOAuth
//
// Initiate OAuth authentication flow.
//
// Generates OAuth state and nonce tokens, then returns the provider's
// authorization URL for the user to complete authentication.
//
// Consumes:
//   - application/json
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: initiateOAuthResponse
//	400: authErrorResponse
//	500: authErrorResponse
//
// InitiateOAuth prepares an OAuth login by issuing a state token.
func (h *Handler) InitiateOAuth(c *gin.Context) {
	h.initiateOAuth(c, model.OAuthPurposeLogin, nil)
}

// swagger:route PUT /api/v1/me/login-methods/{provider} me startBindLoginMethod
//
// Initiate OAuth login-method binding for the authenticated user.
//
// Requires an authenticated fresh session. Generates OAuth state bound to the
// current user and returns the provider authorization URL.
//
// Consumes:
//   - application/json
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: initiateOAuthResponse
//	401: authErrorResponse
//	403: authErrorResponse
//	400: authErrorResponse
//	500: authErrorResponse
func (h *Handler) StartBindLoginMethod(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.UnauthorizedWithCode(c, "UNAUTHORIZED", "user not authenticated", nil)
		return
	}
	h.initiateOAuth(c, model.OAuthPurposeBindLoginMethod, &userID)
}

func (h *Handler) initiateOAuth(c *gin.Context, purpose model.OAuthPurpose, userID *uint64) {
	provider := strings.ToLower(c.Param("provider"))
	providerCfg, ok := h.resolveProvider(provider)
	if !ok {
		response.BadRequest(c, "unsupported provider")
		return
	}

	var req initiateOAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if !errors.Is(err, io.EOF) {
			response.BadRequest(c, err.Error())
			return
		}
	}

	state, err := randomToken(32)
	if err != nil {
		response.InternalServerError(c, "failed to generate state")
		return
	}
	nonce, err := randomToken(24)
	if err != nil {
		response.InternalServerError(c, "failed to generate nonce")
		return
	}

	// Generate PKCE code verifier and challenge
	codeVerifier, codeChallenge, err := generatePKCE()
	if err != nil {
		response.InternalServerError(c, "failed to generate PKCE")
		return
	}

	redirectURL := strings.TrimSpace(req.RedirectTo)
	if redirectURL == "" {
		redirectURL = providerCfg.RedirectURL
	}
	if redirectURL == "" {
		redirectURL = h.cfg.DefaultOAuthRedirectURL
	}

	stateTTL := time.Duration(h.cfg.OAuthStateTTLSeconds) * time.Second
	if stateTTL <= 0 {
		stateTTL = 5 * time.Minute
	}
	expiry := time.Now().UTC().Add(stateTTL)

	stateRecord := model.UserOAuthState{
		Provider:     provider,
		State:        state,
		Purpose:      string(purpose),
		RedirectTo:   redirectURL,
		Nonce:        nonce,
		CodeVerifier: codeVerifier, // Store for later verification
		ClientIP:     c.ClientIP(),
		UserAgent:    truncateUserAgent(c.GetHeader("User-Agent")),
		ExpiresAt:    expiry,
	}
	if userID != nil {
		stateRecord.UserID = sql.NullInt64{Int64: int64(*userID), Valid: true}
	}
	if err := h.db.Create(&stateRecord).Error; err != nil {
		response.InternalServerError(c, "failed to persist oauth state")
		return
	}

	authURL, err := buildAuthURL(providerCfg, redirectURL, state, nonce, codeChallenge)
	if err != nil {
		response.InternalServerError(c, "failed to build auth url")
		return
	}

	responseData := map[string]interface{}{
		"auth_url":   authURL,
		"state":      state,
		"expires_at": expiry.Format(time.RFC3339),
		"purpose":    string(purpose),
	}
	response.Success(c, responseData)
}

type oauthCallbackRequest struct {
	State string `json:"state" binding:"required"`
	Code  string `json:"code" binding:"required"` // Authorization code from provider
}

// swagger:route POST /api/v1/auth/oauth/{provider}/callback auth handleOAuthCallback
//
// Handle OAuth provider callback.
//
// Processes the OAuth callback after user authorization at the provider.
// Creates or updates the user account and returns JWT tokens.
//
// Consumes:
//   - application/json
//
// Produces:
//   - application/json
//
// Security:
//   - none
//
// Responses:
//
//	200: oauthCallbackResponse
//	400: authErrorResponse
//	401: authErrorResponse
//	403: authErrorResponse
//	409: authErrorResponse
//	500: authErrorResponse
//
// HandleOAuthCallback processes the OAuth callback and issues a local session.
// Login-purpose callbacks return a login session payload; bind-purpose callbacks return
// a bind result payload for the authenticated user. Bind-purpose callbacks require the
// current authenticated user to match the persisted state owner.
func (h *Handler) HandleOAuthCallback(c *gin.Context) {
	provider := strings.ToLower(c.Param("provider"))
	providerCfg, ok := h.resolveProvider(provider)
	if !ok {
		response.BadRequest(c, "unsupported provider")
		return
	}

	var req oauthCallbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	now := time.Now().UTC()
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Step 1: Atomically consume the OAuth state. This single transaction
	// covers SELECT (FOR UPDATE), expiry check, IP/UA binding check, bind
	// pre-authorization, and DELETE — preventing the TOCTOU window the
	// previous separate-statement implementation allowed (V23).
	stateRecordPtr, err := h.consumeOAuthState(c, provider, req.State, now)
	if err != nil {
		switch {
		case errors.Is(err, errStateNotFound):
			response.BadRequest(c, "invalid oauth state")
		case errors.Is(err, errStateExpired):
			response.BadRequest(c, "oauth state expired")
		case errors.Is(err, errStateClientChanged):
			// Don't reveal which dimension (IP vs UA) mismatched — the
			// generic "invalid oauth state" matches what an unrelated state
			// would return, denying the attacker an oracle.
			response.BadRequest(c, "invalid oauth state")
		case errors.Is(err, errBindAuthRequired):
			response.UnauthorizedWithCode(c, "UNAUTHORIZED", "bind callback requires authentication", nil)
		case errors.Is(err, errBindUserMismatch):
			response.ForbiddenWithCode(c, "FORBIDDEN", "authenticated user does not match bind state", nil)
		case errors.Is(err, errMissingBindUser):
			response.BadRequest(c, "invalid oauth state")
		default:
			response.InternalServerError(c, "database error")
		}
		return
	}
	stateRecord := *stateRecordPtr

	purpose := oauthPurposeFromState(stateRecord)

	// Step 2: Exchange authorization code for tokens (BACKEND ONLY) with PKCE
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tokenResp, err := h.exchangeCodeForToken(ctx, provider, req.Code, stateRecord.CodeVerifier, providerCfg)
	if err != nil {
		response.BadRequest(c, fmt.Sprintf("token exchange failed: %v", err))
		return
	}

	// Step 2.5: Verify ID token claims (OIDC)
	idTokenClaims, err := h.verifyIDToken(ctx, provider, tokenResp.IDToken, providerCfg, stateRecord.Nonce)
	if err != nil {
		response.BadRequest(c, fmt.Sprintf("ID token validation failed: %v", err))
		return
	}

	// Step 2.6: Validate scopes
	scopeWarnings := validateScopes(providerCfg.Scopes, tokenResp.Scope)
	if len(scopeWarnings) > 0 {
		// Log warnings but don't fail - some providers may grant subset of scopes
		for _, warning := range scopeWarnings {
			log.Printf("[OAuth] Scope warning for provider %s: %s", provider, warning)
		}
	}

	// Step 3: Fetch user info from provider
	userInfo, err := h.fetchUserInfo(ctx, provider, tokenResp.AccessToken, providerCfg, idTokenClaims)
	if err != nil {
		response.BadRequest(c, fmt.Sprintf("failed to fetch user info: %v", err))
		return
	}

	if purpose == model.OAuthPurposeBindLoginMethod {
		err = h.bindOAuthLoginMethod(provider, stateRecord, userInfo, tokenResp, now)
		if err != nil {
			if errors.Is(err, errProviderAlreadyBound) {
				response.ConflictWithCode(c, "PROVIDER_ALREADY_BOUND", "provider account is already bound to another user", nil)
				return
			}
			if errors.Is(err, errProviderRebindConflict) {
				response.ConflictWithCode(c, "PROVIDER_REBIND_CONFLICT", "provider is already bound to a different account on this user", nil)
				return
			}
			if errors.Is(err, errMissingBindUser) {
				response.BadRequest(c, "invalid oauth state")
				return
			}
			response.BadRequest(c, err.Error())
			return
		}

		response.Success(c, map[string]interface{}{
			"provider":            provider,
			"provider_account_id": userInfo.ID,
			"purpose":             string(purpose),
			"user_id":             uint64(stateRecord.UserID.Int64),
			"bound":               true,
		})
		return
	}

	result, err := h.completeOAuthLogin(provider, userInfo, tokenResp, now, clientIP, userAgent)

	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	responseData := map[string]interface{}{
		"user_id":        result.user.ID,
		"access_token":   result.sessionWithTokens.AccessToken,
		"refresh_token":  result.sessionWithTokens.RefreshToken,
		"access_expiry":  result.sessionWithTokens.Session.AccessExpiry.Format(time.RFC3339),
		"refresh_expiry": result.sessionWithTokens.Session.RefreshExpiry.Format(time.RFC3339),
		"email":          emailValue(result.emailRecord),
	}
	response.Success(c, responseData)
}

var (
	errStateNotFound      = errors.New("oauth state not found")
	errStateExpired       = errors.New("oauth state expired")
	errStateClientChanged = errors.New("oauth state client binding mismatch")
)

// consumeOAuthState atomically validates and deletes a one-time OAuth state
// row. The lookup, IP/UA binding check, expiry check, and DELETE all happen
// inside a single transaction with a row-level lock (FOR UPDATE), so two
// concurrent callbacks cannot both succeed for the same state value (V23).
//
// On success the returned record carries the original Nonce/CodeVerifier so
// the caller can finish the OAuth code exchange. The row is already gone
// from the DB by the time this function returns.
//
// Failure modes and their state-row side effects:
//
//   - errStateNotFound: row missing (already consumed, never existed). No-op.
//   - errStateExpired:  row is expired. We DELETE it (committed) so it can't
//     be retried.
//   - errStateClientChanged: IP and/or UA does not match the value captured
//     at state creation. We DELETE it (committed). Strict full-IP equality
//     is documented in the schema migration; mobile NAT can cause false
//     positives, which we accept for now.
//   - errBindAuthRequired / errBindUserMismatch: bind-purpose pre-check
//     failed; the row is PRESERVED so the legitimate user can retry the
//     callback after authenticating. (This matches the historical contract
//     documented by TestHandleOAuthCallbackDoesNotConsumeStateWhenBindCallbackIsUnauthorized.)
//
// Implementation notes: the SELECT below uses
// `Clauses(clause.Locking{Strength: "UPDATE"})` to inject `FOR UPDATE` —
// this is the GORM v2 idiom. The pre-fix v1 idiom
// `Set("gorm:query_option", "FOR UPDATE")` is silently ignored in v2 and
// emits a plain SELECT, which would defeat V23 atomicity entirely. A
// regression test (TestConsumeOAuthState_EmitsForUpdateInSelect) captures
// the rendered SQL and asserts the lock clause is present.
//
// Concurrent consume attempts therefore serialize at the SELECT FOR UPDATE.
// The success-path DELETE additionally checks RowsAffected == 1 so that if
// (despite the lock) two transactions ever both reached the DELETE, only
// one wins; the loser sees RowsAffected == 0 and returns errStateNotFound,
// matching the "row already consumed" semantics expected by the caller.
func (h *Handler) consumeOAuthState(c *gin.Context, provider, state string, now time.Time) (*model.UserOAuthState, error) {
	clientIP := c.ClientIP()
	userAgent := truncateUserAgent(c.GetHeader("User-Agent"))

	tx := h.db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var record model.UserOAuthState
	// Critical: clause.Locking{Strength: "UPDATE"} is the GORM v2 way to
	// emit `FOR UPDATE`. Do NOT regress to `Set("gorm:query_option", ...)`
	// — that is a v1 idiom and is a no-op in v2 (verified empirically by
	// TestConsumeOAuthState_EmitsForUpdateInSelect; the previous code path
	// emitted a plain SELECT with no lock).
	if err := tx.
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("state = ? AND provider = ?", state, provider).
		First(&record).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errStateNotFound
		}
		return nil, err
	}

	if now.After(record.ExpiresAt) {
		if delErr := tx.Delete(&record).Error; delErr != nil {
			return nil, delErr
		}
		if commitErr := tx.Commit().Error; commitErr != nil {
			return nil, commitErr
		}
		committed = true
		return nil, errStateExpired
	}

	// Strict client-binding check. Use constant-time equality (V18) for
	// values an attacker could plausibly manipulate via header injection.
	// Empty stored values are treated as mismatch — production state rows
	// always carry a non-empty IP, and accepting "" would let pre-fix rows
	// pass the check.
	if !secsubtle.StringEqual(record.ClientIP, clientIP) || !secsubtle.StringEqual(record.UserAgent, userAgent) {
		if delErr := tx.Delete(&record).Error; delErr != nil {
			return nil, delErr
		}
		if commitErr := tx.Commit().Error; commitErr != nil {
			return nil, commitErr
		}
		committed = true
		return nil, errStateClientChanged
	}

	// Bind-purpose pre-authorization. Failures must NOT delete the row —
	// see the long-standing test guarantees referenced in the doc above.
	if oauthPurposeFromState(record) == model.OAuthPurposeBindLoginMethod {
		if authErr := h.authorizeBindCallback(c, record); authErr != nil {
			// Roll back; row preserved.
			return nil, authErr
		}
	}

	// All checks passed; consume the row inside the same tx so a concurrent
	// caller cannot also succeed.
	//
	// Defense-in-depth: GORM v2's Delete returns nil error even when zero
	// rows match (i.e., the row was already deleted by a concurrent
	// transaction we somehow didn't serialize against). Insist on
	// RowsAffected == 1 so a "lost the race" caller cannot silently proceed
	// to the OAuth code exchange a second time.
	res := tx.Delete(&record)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected != 1 {
		return nil, errStateNotFound
	}
	if commitErr := tx.Commit().Error; commitErr != nil {
		return nil, commitErr
	}
	committed = true
	return &record, nil
}

// truncateUserAgent caps a User-Agent header at the storage column width
// (255). We truncate by byte rather than by rune because the column is
// VARCHAR(255) in utf8mb4 — runes are not the right unit. The few bytes of
// truncation we may perform on multi-byte UA strings is acceptable; the UA
// is only used for state binding equality, and we apply the same truncation
// at both creation and consumption time.
func truncateUserAgent(ua string) string {
	const max = 255
	if len(ua) <= max {
		return ua
	}
	return ua[:max]
}

func (h *Handler) resolveProvider(provider string) (config.OAuthProviderConfig, bool) {
	if provider == "" {
		return config.OAuthProviderConfig{}, false
	}

	var allowed bool
	if len(h.cfg.AllowedOAuthProviders) == 0 {
		allowed = true
	} else {
		for _, p := range h.cfg.AllowedOAuthProviders {
			if strings.EqualFold(p, provider) {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		return config.OAuthProviderConfig{}, false
	}

	if h.cfg.OAuthProviders == nil {
		return config.OAuthProviderConfig{}, false
	}

	providerCfg, ok := h.cfg.OAuthProviders[provider]
	if ok {
		return providerCfg, true
	}

	// fall back to case-insensitive lookup
	for key, value := range h.cfg.OAuthProviders {
		if strings.EqualFold(key, provider) {
			return value, true
		}
	}
	return config.OAuthProviderConfig{}, false
}

func buildAuthURL(cfg config.OAuthProviderConfig, redirectURL, state, nonce, codeChallenge string) (string, error) {
	if cfg.AuthURL == "" {
		return "", fmt.Errorf("missing auth url for provider")
	}
	authURL, err := url.Parse(cfg.AuthURL)
	if err != nil {
		return "", err
	}
	query := authURL.Query()
	query.Set("client_id", cfg.ClientID)
	if redirectURL != "" {
		query.Set("redirect_uri", redirectURL)
	} else if cfg.RedirectURL != "" {
		query.Set("redirect_uri", cfg.RedirectURL)
	}
	query.Set("response_type", "code")
	if len(cfg.Scopes) > 0 {
		query.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	query.Set("state", state)
	if nonce != "" {
		query.Set("nonce", nonce)
	}
	// Add PKCE parameters (RFC 7636)
	if codeChallenge != "" {
		query.Set("code_challenge", codeChallenge)
		query.Set("code_challenge_method", "S256") // SHA-256
	}
	authURL.RawQuery = query.Encode()
	return authURL.String(), nil
}

func emailValue(email *model.UserEmail) string {
	if email == nil {
		return ""
	}
	return email.Email
}

type oauthLoginResult struct {
	user              model.User
	emailRecord       *model.UserEmail
	sessionWithTokens *SessionWithTokens
}

func oauthPurposeFromState(state model.UserOAuthState) model.OAuthPurpose {
	if strings.EqualFold(state.Purpose, string(model.OAuthPurposeBindLoginMethod)) {
		return model.OAuthPurposeBindLoginMethod
	}
	return model.OAuthPurposeLogin
}

func (h *Handler) authorizeBindCallback(c *gin.Context, stateRecord model.UserOAuthState) error {
	if !stateRecord.UserID.Valid || stateRecord.UserID.Int64 <= 0 {
		return errMissingBindUser
	}

	authenticatedUserID, ok := middleware.GetUserID(c)
	if !ok || authenticatedUserID == 0 {
		return errBindAuthRequired
	}
	if authenticatedUserID != uint64(stateRecord.UserID.Int64) {
		return errBindUserMismatch
	}

	middlewareService := &service.ServiceGroupApp.UserServiceGroup.MiddlewareService
	userPtr, err := middlewareService.GetUserByID(authenticatedUserID)
	if err != nil {
		return err
	}
	if userPtr == nil || userPtr.Status != model.UserStatusActive {
		return errBindAuthRequired
	}
	return nil
}

func (h *Handler) bindOAuthLoginMethod(provider string, stateRecord model.UserOAuthState, userInfo *oauthUserInfo, tokenResp *oauthTokenResponse, now time.Time) error {
	if !stateRecord.UserID.Valid || stateRecord.UserID.Int64 <= 0 {
		return errMissingBindUser
	}

	return h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&model.User{}, stateRecord.UserID.Int64).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errMissingBindUser
			}
			return err
		}

		credential, err := buildOAuthCredential(uint64(stateRecord.UserID.Int64), provider, userInfo.ID, tokenResp, now)
		if err != nil {
			return err
		}

		var existing model.UserCredential
		err = tx.Where("user_id = ? AND provider = ?", stateRecord.UserID.Int64, provider).First(&existing).Error
		if err == nil {
			if existing.ProviderAccountID != userInfo.ID {
				return errProviderRebindConflict
			}

			existing.TokenExpiry = credential.TokenExpiry
			existing.Scopes = credential.Scopes
			existing.LastSyncAt = credential.LastSyncAt
			existing.AccessToken = credential.AccessToken
			existing.RefreshToken = credential.RefreshToken
			return tx.Save(&existing).Error
		}
		if err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
		}

		err = tx.Where("provider = ? AND provider_account_id = ?", provider, userInfo.ID).First(&existing).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return tx.Create(credential).Error
		}
		if err != nil {
			return err
		}
		if existing.UserID != uint64(stateRecord.UserID.Int64) {
			return errProviderAlreadyBound
		}

		existing.TokenExpiry = credential.TokenExpiry
		existing.Scopes = credential.Scopes
		existing.LastSyncAt = credential.LastSyncAt
		existing.AccessToken = credential.AccessToken
		existing.RefreshToken = credential.RefreshToken
		return tx.Save(&existing).Error
	})
}

func (h *Handler) completeOAuthLogin(provider string, userInfo *oauthUserInfo, tokenResp *oauthTokenResponse, now time.Time, clientIP, userAgent string) (*oauthLoginResult, error) {
	result := &oauthLoginResult{}

	err := h.db.Transaction(func(tx *gorm.DB) error {
		var credential model.UserCredential
		credErr := tx.Where("provider = ? AND provider_account_id = ?", provider, userInfo.ID).First(&credential).Error
		if credErr != nil && !errors.Is(credErr, gorm.ErrRecordNotFound) {
			return credErr
		}

		// New user
		if errors.Is(credErr, gorm.ErrRecordNotFound) {
			result.user = model.User{
				PrimaryLoginType: loginTypeForOAuthProvider(provider),
				Status:           model.UserStatusActive,
			}
			if err := tx.Create(&result.user).Error; err != nil {
				return err
			}

			displayName := strings.TrimSpace(userInfo.Name)
			if displayName == "" {
				displayName = fmt.Sprintf("%s_user_%s", provider, userInfo.ID)
			}

			profile := model.UserProfile{
				UserID:      result.user.ID,
				DisplayName: displayName,
				AvatarURL:   userInfo.Picture,
				Locale:      "en_US",
			}
			if err := tx.Create(&profile).Error; err != nil {
				return err
			}

			if email := strings.TrimSpace(strings.ToLower(userInfo.Email)); email != "" {
				var existingEmail model.UserEmail
				emailExists := tx.Where("email = ?", email).First(&existingEmail).Error == nil

				if emailExists {
					log.Printf("[OAuth] Email conflict: %s from %s provider already exists for user_id=%d", piiutil.MaskEmail(email), provider, existingEmail.UserID)
				} else {
					emailModel := model.UserEmail{
						UserID:    result.user.ID,
						Email:     email,
						IsPrimary: true,
					}
					if userInfo.EmailVerified {
						emailModel.VerifiedAt = shared.MakeNullTime(now)
					}
					if err := tx.Create(&emailModel).Error; err != nil {
						return err
					}
					result.emailRecord = &emailModel
				}
			}

			newCredential, err := buildOAuthCredential(result.user.ID, provider, userInfo.ID, tokenResp, now)
			if err != nil {
				return err
			}
			if err := tx.Create(newCredential).Error; err != nil {
				return err
			}
		} else {
			if err := tx.First(&result.user, credential.UserID).Error; err != nil {
				return err
			}

			updatedCredential, err := buildOAuthCredential(result.user.ID, provider, userInfo.ID, tokenResp, now)
			if err != nil {
				return err
			}
			credential.TokenExpiry = updatedCredential.TokenExpiry
			credential.Scopes = updatedCredential.Scopes
			credential.LastSyncAt = updatedCredential.LastSyncAt
			credential.AccessToken = updatedCredential.AccessToken
			credential.RefreshToken = updatedCredential.RefreshToken

			if err := tx.Save(&credential).Error; err != nil {
				return err
			}

			if email := strings.TrimSpace(strings.ToLower(userInfo.Email)); email != "" {
				var userEmail model.UserEmail
				err := tx.Where("user_id = ? AND email = ?", result.user.ID, email).First(&userEmail).Error
				if err != nil {
					if errors.Is(err, gorm.ErrRecordNotFound) {
						var conflictEmail model.UserEmail
						conflict := tx.Where("email = ?", email).First(&conflictEmail).Error == nil

						if conflict {
							log.Printf("[OAuth] Email conflict on update: %s from %s provider already exists for user_id=%d (current user_id=%d)", piiutil.MaskEmail(email), provider, conflictEmail.UserID, result.user.ID)
						} else {
							userEmail = model.UserEmail{
								UserID:    result.user.ID,
								Email:     email,
								IsPrimary: false,
							}
							if userInfo.EmailVerified {
								userEmail.VerifiedAt = shared.MakeNullTime(now)
							}
							if err := tx.Create(&userEmail).Error; err != nil {
								return err
							}
							result.emailRecord = &userEmail
						}
					} else {
						return err
					}
				} else if userInfo.EmailVerified && !userEmail.VerifiedAt.Valid {
					userEmail.VerifiedAt = shared.MakeNullTime(now)
					if err := tx.Save(&userEmail).Error; err != nil {
						return err
					}
					result.emailRecord = &userEmail
				} else {
					result.emailRecord = &userEmail
				}
			}
		}

		updates := map[string]interface{}{
			"last_login_at": shared.MakeNullTime(now),
		}
		if result.user.Status == model.UserStatusPending {
			updates["status"] = model.UserStatusActive
		}
		if err := tx.Model(&model.User{}).Where("id = ?", result.user.ID).Updates(updates).Error; err != nil {
			return err
		}

		var err error
		result.sessionWithTokens, err = h.issueSession(tx, result.user.ID, clientIP, userAgent)
		if err != nil {
			return err
		}

		return h.recordLoginAudit(tx, model.LoginAudit{
			UserID:    sql.NullInt64{Int64: int64(result.user.ID), Valid: true},
			Provider:  provider,
			Success:   true,
			ClientIP:  clientIP,
			UserAgent: userAgent,
			Message:   "oauth login success",
		})
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func buildOAuthCredential(userID uint64, provider, providerAccountID string, tokenResp *oauthTokenResponse, now time.Time) (*model.UserCredential, error) {
	tokenExpiry := shared.ClearNullTime()
	if tokenResp.ExpiresIn > 0 {
		tokenExpiry = shared.MakeNullTime(now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second))
	}

	credential := &model.UserCredential{
		UserID:            userID,
		Provider:          provider,
		ProviderAccountID: providerAccountID,
		TokenExpiry:       tokenExpiry,
		Scopes:            strings.TrimSpace(tokenResp.Scope),
		LastSyncAt:        shared.MakeNullTime(now),
	}
	if err := credential.SetAccessToken(tokenResp.AccessToken); err != nil {
		return nil, fmt.Errorf("encrypt access token: %w", err)
	}
	if err := credential.SetRefreshToken(tokenResp.RefreshToken); err != nil {
		return nil, fmt.Errorf("encrypt refresh token: %w", err)
	}
	return credential, nil
}

func loginTypeForOAuthProvider(provider string) model.LoginType {
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch provider {
	case string(model.LoginTypeGoogle):
		return model.LoginTypeGoogle
	case string(model.LoginTypeGithub):
		return model.LoginTypeGithub
	case string(model.LoginTypeTelegram):
		return model.LoginTypeTelegram
	default:
		return model.LoginType(provider)
	}
}

// OAuth token response structures
type oauthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token,omitempty"` // For OIDC providers
}

type oauthUserInfo struct {
	ID            string `json:"id"` // Provider user ID
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	// GitHub specific
	Login     string `json:"login"`
	AvatarURL string `json:"avatar_url"`
}

type oidcIDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce             string `json:"nonce,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Picture           string `json:"picture,omitempty"`
	PhoneNumber       string `json:"phone_number,omitempty"`
}

// exchangeCodeForToken exchanges an authorization code for OAuth tokens
// This is the secure backend token exchange - keeps client_secret safe
// Uses PKCE code_verifier for additional security
func (h *Handler) exchangeCodeForToken(ctx context.Context, provider, code, codeVerifier string, cfg config.OAuthProviderConfig) (*oauthTokenResponse, error) {
	if cfg.TokenURL == "" {
		return nil, fmt.Errorf("token_url not configured for provider %s", provider)
	}

	// Build token exchange request
	data := url.Values{
		"grant_type": []string{"authorization_code"},
		"code":       []string{code},
		"client_id":  []string{cfg.ClientID},
	}
	if !strings.EqualFold(provider, "telegram") {
		data.Set("client_secret", cfg.ClientSecret)
	}

	if cfg.RedirectURL != "" {
		data.Set("redirect_uri", cfg.RedirectURL)
	}

	// Add PKCE code_verifier
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", cfg.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if strings.EqualFold(provider, "telegram") && cfg.ClientID != "" && cfg.ClientSecret != "" {
		credentials := base64.StdEncoding.EncodeToString([]byte(cfg.ClientID + ":" + cfg.ClientSecret))
		req.Header.Set("Authorization", "Basic "+credentials)
	}

	// Execute request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var tokenResp oauthTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("no access_token in response")
	}

	return &tokenResp, nil
}

// fetchUserInfo retrieves user information from the OAuth provider
func (h *Handler) fetchUserInfo(ctx context.Context, provider, accessToken string, cfg config.OAuthProviderConfig, idTokenClaims *oidcIDTokenClaims) (*oauthUserInfo, error) {
	if strings.EqualFold(provider, "telegram") {
		return oauthUserInfoFromTelegramClaims(idTokenClaims)
	}

	if cfg.UserInfoURL == "" {
		return nil, fmt.Errorf("user_info_url not configured for provider %s", provider)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", cfg.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create userinfo request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute userinfo request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read userinfo response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var userInfo oauthUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("parse userinfo response: %w", err)
	}

	// Normalize provider-specific fields
	switch provider {
	case "github":
		if userInfo.ID == "" && userInfo.Login != "" {
			// GitHub uses 'id' as number, but we need string
			// The ID field should already be populated by JSON unmarshal
		}
		if userInfo.Name == "" && userInfo.Login != "" {
			userInfo.Name = userInfo.Login
		}
		if userInfo.Picture == "" && userInfo.AvatarURL != "" {
			userInfo.Picture = userInfo.AvatarURL
		}
	}

	if userInfo.ID == "" {
		return nil, fmt.Errorf("provider did not return user ID")
	}

	return &userInfo, nil
}

// verifyIDToken validates an OIDC ID token and returns its claims.
//
// Telegram has its own legacy verification path (verifyTelegramIDToken) and
// is preserved for backward compatibility. Every other provider goes through
// the strict internal/oidc.Verifier — there is NO ParseUnverified fallback,
// missing OIDC config fails closed at this call site (see V3 hardening).
func (h *Handler) verifyIDToken(ctx context.Context, provider, idToken string, cfg config.OAuthProviderConfig, expectedNonce string) (*oidcIDTokenClaims, error) {
	if idToken == "" {
		// Not all providers return ID tokens (e.g., GitHub doesn't); the caller
		// handles that case via fetchUserInfo. Returning nil here is safe ONLY
		// because subsequent code does not trust nil claims for identity.
		return nil, nil
	}

	if strings.EqualFold(provider, "telegram") {
		return verifyTelegramIDToken(ctx, idToken, cfg.ClientID, expectedNonce)
	}

	if h == nil || h.oidcVerifiers == nil {
		return nil, errors.New("oidc verifier cache not initialized")
	}
	verifier, err := h.oidcVerifiers.verifierFor(provider, cfg)
	if err != nil {
		return nil, fmt.Errorf("oidc verifier unavailable: %w", err)
	}
	claims, err := verifier.Verify(ctx, idToken, expectedNonce)
	if err != nil {
		return nil, err
	}
	return convertOIDCClaims(claims), nil
}

// convertOIDCClaims maps internal/oidc.Claims to the legacy
// oidcIDTokenClaims used by the rest of the auth handler. Keeping the legacy
// shape avoids a sweeping rename across fetchUserInfo etc. — those code paths
// can be unified in a follow-up task.
func convertOIDCClaims(c *oidc.Claims) *oidcIDTokenClaims {
	if c == nil {
		return nil
	}
	return &oidcIDTokenClaims{
		RegisteredClaims:  c.RegisteredClaims,
		Nonce:             c.Nonce,
		Name:              c.Name,
		PreferredUsername: c.PreferredUsername,
		Picture:           c.Picture,
	}
}

func verifyTelegramIDToken(ctx context.Context, idToken, clientID, expectedNonce string) (*oidcIDTokenClaims, error) {
	claims := &oidcIDTokenClaims{}
	token, err := jwt.ParseWithClaims(idToken, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}

		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("missing key id in token header")
		}

		return fetchTelegramJWKSKey(ctx, kid)
	}, jwt.WithAudience(clientID), jwt.WithIssuer(telegramOIDCIssuer), jwt.WithLeeway(time.Minute))
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid ID token")
	}

	// Strict nonce policy, matching internal/oidc.Verifier.validateClaims.
	//
	// The pre-fix condition `expectedNonce != "" && claims.Nonce != "" &&
	// !secsubtle.StringEqual(...)` had a bypass: a token with NO nonce
	// claim made the middle conjunct false and the whole check passed.
	// That let an attacker replay a no-nonce id_token across sessions even
	// when the server had bound a specific nonce to the OAuth state. The
	// V3 OIDC verifier closes this for non-Telegram providers; preserving
	// the bypass on the Telegram path defeats the hardening, so we mirror
	// the strict policy here.
	if expectedNonce != "" {
		if claims.Nonce == "" || !secsubtle.StringEqual(claims.Nonce, expectedNonce) {
			return nil, errors.New("ID token nonce mismatch")
		}
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("missing subject in ID token")
	}

	return claims, nil
}

func fetchTelegramJWKSKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, telegramOIDCJWKSURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create jwks request: %w", err)
	}

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("fetch jwks failed with status %d: %s", resp.StatusCode, string(body))
	}

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}

	for _, key := range jwks.Keys {
		if key.Kid != kid {
			continue
		}
		if key.Kty != "RSA" {
			return nil, fmt.Errorf("unsupported jwk type: %s", key.Kty)
		}

		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return nil, fmt.Errorf("decode jwk modulus: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return nil, fmt.Errorf("decode jwk exponent: %w", err)
		}

		e := new(big.Int).SetBytes(eBytes)
		if !e.IsInt64() {
			return nil, fmt.Errorf("invalid jwk exponent")
		}

		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(e.Int64()),
		}, nil
	}

	return nil, fmt.Errorf("no jwk found for kid %s", kid)
}

func oauthUserInfoFromTelegramClaims(claims *oidcIDTokenClaims) (*oauthUserInfo, error) {
	if claims == nil {
		return nil, fmt.Errorf("missing telegram id token claims")
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("telegram id token missing subject")
	}

	userInfo := &oauthUserInfo{
		ID:      claims.Subject,
		Name:    strings.TrimSpace(claims.Name),
		Picture: strings.TrimSpace(claims.Picture),
		Login:   strings.TrimSpace(claims.PreferredUsername),
	}
	if userInfo.Name == "" {
		userInfo.Name = userInfo.Login
	}
	return userInfo, nil
}

// refreshOAuthToken refreshes an expired OAuth access token using refresh token
func (h *Handler) refreshOAuthToken(ctx context.Context, credential *model.UserCredential, cfg config.OAuthProviderConfig) error {
	if cfg.TokenURL == "" {
		return fmt.Errorf("token_url not configured for provider %s", credential.Provider)
	}

	// Decrypt refresh token
	refreshToken, err := credential.GetRefreshToken()
	if err != nil {
		return fmt.Errorf("decrypt refresh token: %w", err)
	}

	if refreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	// Build token refresh request
	data := url.Values{
		"grant_type":    []string{"refresh_token"},
		"refresh_token": []string{refreshToken},
		"client_id":     []string{cfg.ClientID},
		"client_secret": []string{cfg.ClientSecret},
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", cfg.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Execute request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("execute refresh request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token refresh failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var tokenResp oauthTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return fmt.Errorf("parse refresh response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return fmt.Errorf("no access_token in refresh response")
	}

	// Update credential with new tokens (encrypted)
	now := time.Now().UTC()

	if err := credential.SetAccessToken(tokenResp.AccessToken); err != nil {
		return fmt.Errorf("encrypt new access token: %w", err)
	}

	// Some providers issue new refresh token on refresh
	if tokenResp.RefreshToken != "" {
		if err := credential.SetRefreshToken(tokenResp.RefreshToken); err != nil {
			return fmt.Errorf("encrypt new refresh token: %w", err)
		}
	}

	// Update token expiry
	if tokenResp.ExpiresIn > 0 {
		credential.TokenExpiry = shared.MakeNullTime(now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second))
	} else {
		credential.TokenExpiry = shared.ClearNullTime()
	}

	credential.LastSyncAt = shared.MakeNullTime(now)

	// Save to database
	if err := h.db.Save(credential).Error; err != nil {
		return fmt.Errorf("save refreshed credential: %w", err)
	}

	return nil
}

// RefreshOAuthTokenPublic is a public wrapper for refreshOAuthToken
// Used by background workers to refresh expiring tokens
func (h *Handler) RefreshOAuthTokenPublic(ctx context.Context, credential *model.UserCredential, cfg config.OAuthProviderConfig) error {
	return h.refreshOAuthToken(ctx, credential, cfg)
}

// validateScopes checks if granted scopes meet minimum requirements
// Returns warning messages if critical scopes are missing
func validateScopes(requested []string, granted string) []string {
	if len(requested) == 0 {
		return nil // No scope requirements
	}

	// Parse granted scopes (space-separated string)
	grantedMap := make(map[string]bool)
	for _, scope := range strings.Split(granted, " ") {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			grantedMap[scope] = true
		}
	}

	var warnings []string
	for _, reqScope := range requested {
		if !grantedMap[reqScope] {
			warnings = append(warnings, fmt.Sprintf("scope '%s' was requested but not granted", reqScope))
		}
	}

	return warnings
}

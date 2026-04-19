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
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/handler/shared"
	"paigram/internal/middleware"
	"paigram/internal/model"
	"paigram/internal/response"
)

var (
	telegramOIDCIssuer      = "https://oauth.telegram.org"
	telegramOIDCJWKSURL     = "https://oauth.telegram.org/.well-known/jwks.json"
	errProviderAlreadyBound = errors.New("provider already bound to another user")
	errMissingBindUser      = errors.New("missing oauth bind user")
)

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
//	200: loginResponse
//	400: authErrorResponse
//	401: authErrorResponse
//	404: authErrorResponse
//	409: authErrorResponse
//	500: authErrorResponse
//
// HandleOAuthCallback processes the OAuth callback and issues a local session.
// Now performs secure backend token exchange - frontend only sends authorization code.
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

	// Step 1: Validate OAuth state
	var stateRecord model.UserOAuthState
	if err := h.db.Where("state = ? AND provider = ?", req.State, provider).First(&stateRecord).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.BadRequest(c, "invalid oauth state")
		} else {
			response.InternalServerError(c, "database error")
		}
		return
	}

	if now.After(stateRecord.ExpiresAt) {
		_ = h.db.Delete(&stateRecord)
		response.BadRequest(c, "oauth state expired")
		return
	}

	// Delete state (one-time use)
	if err := h.db.Delete(&stateRecord).Error; err != nil {
		response.InternalServerError(c, "failed to delete oauth state")
		return
	}

	// Step 2: Exchange authorization code for tokens (BACKEND ONLY) with PKCE
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tokenResp, err := h.exchangeCodeForToken(ctx, provider, req.Code, stateRecord.CodeVerifier, providerCfg)
	if err != nil {
		response.BadRequest(c, fmt.Sprintf("token exchange failed: %v", err))
		return
	}

	// Step 2.5: Verify ID token claims (OIDC)
	idTokenClaims, err := verifyIDToken(ctx, provider, tokenResp.IDToken, providerCfg, stateRecord.Nonce)
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

	purpose := oauthPurposeFromState(stateRecord)
	if purpose == model.OAuthPurposeBindLoginMethod {
		err = h.bindOAuthLoginMethod(provider, stateRecord, userInfo, tokenResp, now)
		if err != nil {
			if errors.Is(err, errProviderAlreadyBound) {
				response.ConflictWithCode(c, "PROVIDER_ALREADY_BOUND", "provider account is already bound to another user", nil)
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
					log.Printf("[OAuth] Email conflict: %s from %s provider already exists for user_id=%d", email, provider, existingEmail.UserID)
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
							log.Printf("[OAuth] Email conflict on update: %s from %s provider already exists for user_id=%d (current user_id=%d)", email, provider, conflictEmail.UserID, result.user.ID)
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
func verifyIDToken(ctx context.Context, provider, idToken string, cfg config.OAuthProviderConfig, expectedNonce string) (*oidcIDTokenClaims, error) {
	if idToken == "" {
		// Not all providers return ID tokens (e.g., GitHub doesn't)
		return nil, nil
	}

	if strings.EqualFold(provider, "telegram") {
		return verifyTelegramIDToken(ctx, idToken, cfg.ClientID, expectedNonce)
	}

	return parseUnverifiedIDToken(idToken, expectedNonce)
}

func parseUnverifiedIDToken(idToken, expectedNonce string) (*oidcIDTokenClaims, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	claims := &oidcIDTokenClaims{}
	token, _, err := parser.ParseUnverified(idToken, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ID token: %w", err)
	}

	parsedClaims, ok := token.Claims.(*oidcIDTokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid ID token claims")
	}

	if expectedNonce != "" && parsedClaims.Nonce != "" && parsedClaims.Nonce != expectedNonce {
		return nil, fmt.Errorf("ID token nonce mismatch: expected %s, got %s", expectedNonce, parsedClaims.Nonce)
	}

	return parsedClaims, nil
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

	if expectedNonce != "" && claims.Nonce != "" && claims.Nonce != expectedNonce {
		return nil, fmt.Errorf("ID token nonce mismatch: expected %s, got %s", expectedNonce, claims.Nonce)
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

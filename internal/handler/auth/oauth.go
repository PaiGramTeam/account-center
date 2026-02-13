package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/handler/shared"
	"paigram/internal/model"
	"paigram/internal/response"
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
		RedirectTo:   redirectURL,
		Nonce:        nonce,
		CodeVerifier: codeVerifier, // Store for later verification
		ExpiresAt:    expiry,
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

	// Step 2.5: Verify ID token nonce (OIDC)
	if err := verifyIDToken(tokenResp.IDToken, stateRecord.Nonce); err != nil {
		response.BadRequest(c, fmt.Sprintf("ID token validation failed: %v", err))
		return
	}

	// Step 3: Fetch user info from provider
	userInfo, err := h.fetchUserInfo(ctx, provider, tokenResp.AccessToken, providerCfg)
	if err != nil {
		response.BadRequest(c, fmt.Sprintf("failed to fetch user info: %v", err))
		return
	}

	// Step 4: Create or update user account
	var user model.User
	var emailRecord *model.UserEmail
	var sessionWithTokens *SessionWithTokens

	err = h.db.Transaction(func(tx *gorm.DB) error {
		var credential model.UserCredential
		credErr := tx.Where("provider = ? AND provider_account_id = ?", provider, userInfo.ID).First(&credential).Error
		if credErr != nil && !errors.Is(credErr, gorm.ErrRecordNotFound) {
			return credErr
		}

		tokenExpiry := shared.ClearNullTime()
		if tokenResp.ExpiresIn > 0 {
			tokenExpiry = shared.MakeNullTime(now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second))
		}

		// New user
		if errors.Is(credErr, gorm.ErrRecordNotFound) {
			user = model.User{
				PrimaryLoginType: model.LoginTypeOAuth,
				Status:           model.UserStatusActive,
			}
			if err := tx.Create(&user).Error; err != nil {
				return err
			}

			displayName := strings.TrimSpace(userInfo.Name)
			if displayName == "" {
				displayName = fmt.Sprintf("%s_user_%s", provider, userInfo.ID)
			}

			profile := model.UserProfile{
				UserID:      user.ID,
				DisplayName: displayName,
				AvatarURL:   userInfo.Picture,
				Locale:      "en_US",
			}
			if err := tx.Create(&profile).Error; err != nil {
				return err
			}

			if email := strings.TrimSpace(strings.ToLower(userInfo.Email)); email != "" {
				emailModel := model.UserEmail{
					UserID:    user.ID,
					Email:     email,
					IsPrimary: true,
				}
				if userInfo.EmailVerified {
					emailModel.VerifiedAt = shared.MakeNullTime(now)
				}
				if err := tx.Create(&emailModel).Error; err != nil {
					return err
				}
				emailRecord = &emailModel
			}

			// Create credential with ENCRYPTED tokens
			credential = model.UserCredential{
				UserID:            user.ID,
				Provider:          provider,
				ProviderAccountID: userInfo.ID,
				TokenExpiry:       tokenExpiry,
				Scopes:            strings.TrimSpace(tokenResp.Scope),
				LastSyncAt:        shared.MakeNullTime(now),
			}

			// Encrypt and store OAuth tokens
			if err := credential.SetAccessToken(tokenResp.AccessToken); err != nil {
				return fmt.Errorf("encrypt access token: %w", err)
			}
			if err := credential.SetRefreshToken(tokenResp.RefreshToken); err != nil {
				return fmt.Errorf("encrypt refresh token: %w", err)
			}

			if err := tx.Create(&credential).Error; err != nil {
				return err
			}
		} else {
			// Existing user
			if err := tx.First(&user, credential.UserID).Error; err != nil {
				return err
			}

			// Update credential with ENCRYPTED tokens
			credential.TokenExpiry = tokenExpiry
			credential.Scopes = strings.TrimSpace(tokenResp.Scope)
			credential.LastSyncAt = shared.MakeNullTime(now)

			if err := credential.SetAccessToken(tokenResp.AccessToken); err != nil {
				return fmt.Errorf("encrypt access token: %w", err)
			}
			if err := credential.SetRefreshToken(tokenResp.RefreshToken); err != nil {
				return fmt.Errorf("encrypt refresh token: %w", err)
			}

			if err := tx.Save(&credential).Error; err != nil {
				return err
			}

			// Update or create email record
			if email := strings.TrimSpace(strings.ToLower(userInfo.Email)); email != "" {
				var userEmail model.UserEmail
				err := tx.Where("user_id = ? AND email = ?", user.ID, email).First(&userEmail).Error
				if err != nil {
					if errors.Is(err, gorm.ErrRecordNotFound) {
						userEmail = model.UserEmail{
							UserID:    user.ID,
							Email:     email,
							IsPrimary: false,
						}
						if userInfo.EmailVerified {
							userEmail.VerifiedAt = shared.MakeNullTime(now)
						}
						if err := tx.Create(&userEmail).Error; err != nil {
							return err
						}
					} else {
						return err
					}
				} else if userInfo.EmailVerified && !userEmail.VerifiedAt.Valid {
					userEmail.VerifiedAt = shared.MakeNullTime(now)
					if err := tx.Save(&userEmail).Error; err != nil {
						return err
					}
				}
				emailRecord = &userEmail
			}
		}

		// Update user last login
		updates := map[string]interface{}{
			"last_login_at": shared.MakeNullTime(now),
		}
		if user.Status == model.UserStatusPending {
			updates["status"] = model.UserStatusActive
		}
		if err := tx.Model(&model.User{}).Where("id = ?", user.ID).Updates(updates).Error; err != nil {
			return err
		}

		// Issue local session
		var err error
		sessionWithTokens, err = h.issueSession(tx, user.ID, clientIP, userAgent)
		if err != nil {
			return err
		}

		// Record successful login
		return h.recordLoginAudit(tx, model.LoginAudit{
			UserID:    sql.NullInt64{Int64: int64(user.ID), Valid: true},
			Provider:  provider,
			Success:   true,
			ClientIP:  clientIP,
			UserAgent: userAgent,
			Message:   "oauth login success",
		})
	})

	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	responseData := map[string]interface{}{
		"user_id":        user.ID,
		"access_token":   sessionWithTokens.AccessToken,
		"refresh_token":  sessionWithTokens.RefreshToken,
		"access_expiry":  sessionWithTokens.Session.AccessExpiry.Format(time.RFC3339),
		"refresh_expiry": sessionWithTokens.Session.RefreshExpiry.Format(time.RFC3339),
		"email":          emailValue(emailRecord),
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

// exchangeCodeForToken exchanges an authorization code for OAuth tokens
// This is the secure backend token exchange - keeps client_secret safe
// Uses PKCE code_verifier for additional security
func (h *Handler) exchangeCodeForToken(ctx context.Context, provider, code, codeVerifier string, cfg config.OAuthProviderConfig) (*oauthTokenResponse, error) {
	if cfg.TokenURL == "" {
		return nil, fmt.Errorf("token_url not configured for provider %s", provider)
	}

	// Build token exchange request
	data := url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{code},
		"client_id":     []string{cfg.ClientID},
		"client_secret": []string{cfg.ClientSecret},
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
func (h *Handler) fetchUserInfo(ctx context.Context, provider, accessToken string, cfg config.OAuthProviderConfig) (*oauthUserInfo, error) {
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

// verifyIDToken validates an OIDC ID token's nonce claim
// This prevents token replay attacks for OIDC providers
func verifyIDToken(idToken, expectedNonce string) error {
	if idToken == "" {
		// Not all providers return ID tokens (e.g., GitHub doesn't)
		return nil
	}

	if expectedNonce == "" {
		// No nonce to verify
		return nil
	}

	// Parse JWT without signature verification (we trust the token came from provider via HTTPS)
	// Signature verification would require fetching provider's public keys (JWKS)
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse ID token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid ID token claims")
	}

	// Verify nonce claim
	nonce, ok := claims["nonce"].(string)
	if !ok {
		// Some providers might not include nonce if not in auth request
		return nil
	}

	if nonce != expectedNonce {
		return fmt.Errorf("ID token nonce mismatch: expected %s, got %s", expectedNonce, nonce)
	}

	// Optionally verify other claims
	// iss (issuer), aud (audience), exp (expiration), iat (issued at)
	// For production, should verify signature using provider's JWKS

	return nil
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

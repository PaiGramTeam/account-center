package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/middleware"
	"paigram/internal/model"
)

func TestStartBindLoginMethodPersistsBindPurposeAndUserID(t *testing.T) {
	db := setupTestDB(t)
	ensureUserOAuthStatesTable(t, db)
	h := setupOAuthTestHandler(db)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/api/v1/me/login-methods/:provider", func(c *gin.Context) {
		middleware.SetUserID(c, 42)
		h.StartBindLoginMethod(c)
	})

	req := httptest.NewRequest(http.MethodPut, "/api/v1/me/login-methods/telegram", bytes.NewBufferString(`{"redirect_to":"https://app.example.com/settings/login-methods"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var payload struct {
		Data struct {
			State string `json:"state"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &payload))
	require.NotEmpty(t, payload.Data.State)

	var persisted struct {
		Purpose string
		UserID  sql.NullInt64
	}
	require.NoError(t, db.Raw("SELECT purpose, user_id FROM user_oauth_states WHERE state = ?", payload.Data.State).Scan(&persisted).Error)
	assert.Equal(t, "bind_login_method", persisted.Purpose)
	require.True(t, persisted.UserID.Valid)
	assert.Equal(t, int64(42), persisted.UserID.Int64)
}

func TestHandleOAuthCallbackReturnsConflictWhenBindingProviderAlreadyBelongsToAnotherUser(t *testing.T) {
	db := setupTestDB(t)
	ensureUserOAuthStatesTable(t, db)
	h := setupOAuthTestHandler(db)

	owner := createTestUser(t, db, "owner@example.com", "Password123!", true)
	binder := createTestUser(t, db, "binder@example.com", "Password123!", true)

	credential := model.UserCredential{
		UserID:            owner.ID,
		Provider:          "telegram",
		ProviderAccountID: "telegram-user-123",
	}
	require.NoError(t, credential.SetAccessToken("owner-access-token"))
	require.NoError(t, credential.SetRefreshToken("owner-refresh-token"))
	require.NoError(t, db.Create(&credential).Error)

	state := model.UserOAuthState{
		Provider:     "telegram",
		State:        "bind-conflict-state",
		RedirectTo:   "https://app.example.com/settings/login-methods",
		Nonce:        "expected-nonce",
		CodeVerifier: "expected-verifier",
		ExpiresAt:    time.Now().UTC().Add(5 * time.Minute),
	}
	require.NoError(t, db.Create(&state).Error)
	require.NoError(t, db.Exec("UPDATE user_oauth_states SET purpose = ?, user_id = ? WHERE id = ?", "bind_login_method", binder.ID, state.ID).Error)

	provider := newTelegramOAuthTestProvider(t, "expected-nonce")
	originalJWKSURL := telegramOIDCJWKSURL
	originalIssuer := telegramOIDCIssuer
	telegramOIDCJWKSURL = provider.jwksURL
	telegramOIDCIssuer = provider.issuer
	t.Cleanup(func() {
		telegramOIDCJWKSURL = originalJWKSURL
		telegramOIDCIssuer = originalIssuer
	})

	h.cfg.AllowedOAuthProviders = []string{"telegram"}
	h.cfg.OAuthProviders = map[string]config.OAuthProviderConfig{
		"telegram": {
			ClientID:     provider.clientID,
			ClientSecret: provider.clientSecret,
			RedirectURL:  "https://app.example.com/auth/callback",
			AuthURL:      "https://oauth.telegram.test/auth",
			TokenURL:     provider.tokenURL,
		},
	}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body := bytes.NewBufferString(`{"state":"bind-conflict-state","code":"provider-code"}`)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/telegram/callback", body)
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "provider", Value: "telegram"}}

	h.HandleOAuthCallback(c)

	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	assert.Equal(t, "PROVIDER_ALREADY_BOUND", decodeOAuthErrorCode(t, w))

	var sessionCount int64
	require.NoError(t, db.Model(&model.UserSession{}).Where("user_id = ?", binder.ID).Count(&sessionCount).Error)
	assert.Zero(t, sessionCount)
}

func TestHandleOAuthCallbackRequiresAuthenticatedSessionForBindPurpose(t *testing.T) {
	db := setupTestDB(t)
	ensureUserOAuthStatesTable(t, db)
	h := setupOAuthTestHandler(db)

	binder := createTestUser(t, db, "binder-no-auth@example.com", "Password123!", true)
	state := model.UserOAuthState{
		Provider:     "telegram",
		State:        "bind-no-auth-state",
		Purpose:      string(model.OAuthPurposeBindLoginMethod),
		UserID:       sql.NullInt64{Int64: int64(binder.ID), Valid: true},
		RedirectTo:   "https://app.example.com/settings/login-methods",
		Nonce:        "expected-nonce",
		CodeVerifier: "expected-verifier",
		ExpiresAt:    time.Now().UTC().Add(5 * time.Minute),
	}
	require.NoError(t, db.Create(&state).Error)

	provider := configureTelegramOAuthProviderForTest(t, h, "expected-nonce")
	_ = provider

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body := bytes.NewBufferString(`{"state":"bind-no-auth-state","code":"provider-code"}`)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/telegram/callback", body)
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "provider", Value: "telegram"}}

	h.HandleOAuthCallback(c)

	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	assert.Equal(t, "UNAUTHORIZED", decodeOAuthErrorCode(t, w))

	assertOAuthStateDeleted(t, db, state.State)
}

func TestHandleOAuthCallbackRejectsBindPurposeForDifferentAuthenticatedUser(t *testing.T) {
	db := setupTestDB(t)
	ensureUserOAuthStatesTable(t, db)
	h := setupOAuthTestHandler(db)

	binder := createTestUser(t, db, "binder-mismatch@example.com", "Password123!", true)
	otherUser := createTestUser(t, db, "other-mismatch@example.com", "Password123!", true)
	state := model.UserOAuthState{
		Provider:     "telegram",
		State:        "bind-mismatch-state",
		Purpose:      string(model.OAuthPurposeBindLoginMethod),
		UserID:       sql.NullInt64{Int64: int64(binder.ID), Valid: true},
		RedirectTo:   "https://app.example.com/settings/login-methods",
		Nonce:        "expected-nonce",
		CodeVerifier: "expected-verifier",
		ExpiresAt:    time.Now().UTC().Add(5 * time.Minute),
	}
	require.NoError(t, db.Create(&state).Error)

	provider := configureTelegramOAuthProviderForTest(t, h, "expected-nonce")
	_ = provider

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body := bytes.NewBufferString(`{"state":"bind-mismatch-state","code":"provider-code"}`)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/telegram/callback", body)
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "provider", Value: "telegram"}}
	middleware.SetUserID(c, otherUser.ID)

	h.HandleOAuthCallback(c)

	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	assert.Equal(t, "FORBIDDEN", decodeOAuthErrorCode(t, w))

	assertOAuthStateDeleted(t, db, state.State)
}

func ensureUserOAuthStatesTable(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Exec(`
		CREATE TABLE IF NOT EXISTS user_oauth_states (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
			provider VARCHAR(64) NOT NULL,
			state VARCHAR(255) NOT NULL,
			purpose VARCHAR(64) NOT NULL,
			user_id BIGINT UNSIGNED NULL,
			redirect_to VARCHAR(512) NULL,
			nonce VARCHAR(255) NULL,
			code_verifier VARCHAR(255) NULL,
			expires_at DATETIME(3) NOT NULL,
			created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
			UNIQUE KEY uniq_state (state),
			KEY idx_provider_expires (provider, expires_at),
			KEY idx_user_oauth_states_purpose (purpose),
			KEY idx_user_oauth_states_user_id (user_id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
	`).Error)
}

func setupOAuthTestHandler(db *gorm.DB) *Handler {
	h := setupTestHandler(db)
	h.cfg.OAuthStateTTLSeconds = 300
	h.cfg.DefaultOAuthRedirectURL = "https://app.example.com/auth/callback"
	return h
}

func configureTelegramOAuthProviderForTest(t *testing.T, h *Handler, nonce string) *telegramOAuthTestProvider {
	t.Helper()

	provider := newTelegramOAuthTestProvider(t, nonce)
	originalJWKSURL := telegramOIDCJWKSURL
	originalIssuer := telegramOIDCIssuer
	telegramOIDCJWKSURL = provider.jwksURL
	telegramOIDCIssuer = provider.issuer
	t.Cleanup(func() {
		telegramOIDCJWKSURL = originalJWKSURL
		telegramOIDCIssuer = originalIssuer
	})

	h.cfg.AllowedOAuthProviders = []string{"telegram"}
	h.cfg.OAuthProviders = map[string]config.OAuthProviderConfig{
		"telegram": {
			ClientID:     provider.clientID,
			ClientSecret: provider.clientSecret,
			RedirectURL:  "https://app.example.com/auth/callback",
			AuthURL:      "https://oauth.telegram.test/auth",
			TokenURL:     provider.tokenURL,
		},
	}

	return provider
}

func assertOAuthStateDeleted(t *testing.T, db *gorm.DB, state string) {
	t.Helper()

	var count int64
	require.NoError(t, db.Model(&model.UserOAuthState{}).Where("state = ?", state).Count(&count).Error)
	assert.Zero(t, count)
}

func decodeOAuthErrorCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()

	var payload map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
	errorData, ok := payload["error"].(map[string]any)
	require.True(t, ok, "expected error response, got %s", recorder.Body.String())
	code, _ := errorData["code"].(string)
	return code
}

type telegramOAuthTestProvider struct {
	clientID     string
	clientSecret string
	issuer       string
	tokenURL     string
	jwksURL      string
	privateKey   *rsa.PrivateKey
	nonce        string
}

func newTelegramOAuthTestProvider(t *testing.T, nonce string) *telegramOAuthTestProvider {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	provider := &telegramOAuthTestProvider{
		clientID:     "123456789",
		clientSecret: "telegram-test-secret",
		issuer:       "https://oauth.telegram.test",
		privateKey:   privateKey,
		nonce:        nonce,
	}

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		payload := map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": "test-kid",
				"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
			}},
		}
		require.NoError(t, json.NewEncoder(w).Encode(payload))
	}))
	t.Cleanup(jwksServer.Close)
	provider.jwksURL = jwksServer.URL

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		idToken := provider.signedIDToken(t)
		_, err := w.Write([]byte(`{"access_token":"access-token","refresh_token":"refresh-token","token_type":"Bearer","expires_in":3600,"scope":"openid profile","id_token":"` + idToken + `"}`))
		require.NoError(t, err)
	}))
	t.Cleanup(tokenServer.Close)
	provider.tokenURL = tokenServer.URL

	return provider
}

func (p *telegramOAuthTestProvider) signedIDToken(t *testing.T) string {
	t.Helper()

	now := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, oidcIDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.issuer,
			Subject:   "telegram-user-123",
			Audience:  jwt.ClaimStrings{p.clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Nonce:             p.nonce,
		Name:              "Telegram Test User",
		PreferredUsername: "telegramuser",
	})
	token.Header["kid"] = "test-kid"

	idToken, err := token.SignedString(p.privateKey)
	require.NoError(t, err)
	return idToken
}

func TestExchangeCodeForTokenTelegramUsesBasicAuth(t *testing.T) {
	var authHeader string
	var form url.Values

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		authHeader = r.Header.Get("Authorization")
		require.NoError(t, r.ParseForm())
		form = r.Form
		_, err = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","expires_in":3600,"id_token":"token"}`))
		require.NoError(t, err)
	}))
	defer server.Close()

	h := &Handler{}
	resp, err := h.exchangeCodeForToken(context.Background(), "telegram", "auth-code", "verifier", config.OAuthProviderConfig{
		ClientID:     "123456789",
		ClientSecret: "secret-value",
		RedirectURL:  "https://example.com/callback",
		TokenURL:     server.URL,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("123456789:secret-value")), authHeader)
	assert.Equal(t, "123456789", form.Get("client_id"))
	assert.Equal(t, "auth-code", form.Get("code"))
	assert.Equal(t, "verifier", form.Get("code_verifier"))
	assert.Empty(t, form.Get("client_secret"))
}

func TestVerifyIDTokenTelegramValidatesSignatureAndClaims(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	originalJWKSURL := telegramOIDCJWKSURL
	originalIssuer := telegramOIDCIssuer
	t.Cleanup(func() {
		telegramOIDCJWKSURL = originalJWKSURL
		telegramOIDCIssuer = originalIssuer
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": "test-kid",
				"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
			}},
		}
		require.NoError(t, json.NewEncoder(w).Encode(payload))
	}))
	defer server.Close()

	telegramOIDCJWKSURL = server.URL
	telegramOIDCIssuer = "https://issuer.example"

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, oidcIDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    telegramOIDCIssuer,
			Subject:   "telegram-user-123",
			Audience:  jwt.ClaimStrings{"123456789"},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Nonce:             "expected-nonce",
		Name:              "John Doe",
		PreferredUsername: "johndoe",
		Picture:           "https://cdn.telegram.org/avatar.jpg",
	})
	token.Header["kid"] = "test-kid"
	idToken, err := token.SignedString(privateKey)
	require.NoError(t, err)

	claims, err := verifyIDToken(context.Background(), "telegram", idToken, config.OAuthProviderConfig{ClientID: "123456789"}, "expected-nonce")
	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, "telegram-user-123", claims.Subject)
	assert.Equal(t, "John Doe", claims.Name)
	assert.Equal(t, "johndoe", claims.PreferredUsername)
}

func TestFetchUserInfoTelegramUsesIDTokenClaims(t *testing.T) {
	h := &Handler{}
	userInfo, err := h.fetchUserInfo(context.Background(), "telegram", "", config.OAuthProviderConfig{}, &oidcIDTokenClaims{
		RegisteredClaims:  jwt.RegisteredClaims{Subject: "telegram-user-123"},
		Name:              "John Doe",
		PreferredUsername: "johndoe",
		Picture:           "https://cdn.telegram.org/avatar.jpg",
	})
	require.NoError(t, err)
	assert.Equal(t, "telegram-user-123", userInfo.ID)
	assert.Equal(t, "John Doe", userInfo.Name)
	assert.Equal(t, "johndoe", userInfo.Login)
	assert.Equal(t, "https://cdn.telegram.org/avatar.jpg", userInfo.Picture)
}

func TestResolveProviderIncludesTelegramConfig(t *testing.T) {
	h := &Handler{cfg: config.AuthConfig{
		AllowedOAuthProviders: []string{"telegram"},
		OAuthProviders: map[string]config.OAuthProviderConfig{
			"telegram": {
				ClientID: "123456789",
				AuthURL:  "https://oauth.telegram.org/auth",
				TokenURL: "https://oauth.telegram.org/token",
				Scopes:   []string{"openid", "profile"},
			},
		},
	}}

	providerCfg, ok := h.resolveProvider("telegram")
	require.True(t, ok)
	assert.Equal(t, "123456789", providerCfg.ClientID)
	assert.True(t, strings.Contains(providerCfg.AuthURL, "oauth.telegram.org"))
}

func TestOAuthProviderLoginTypeUsesConcreteProviderValue(t *testing.T) {
	assert.Equal(t, model.LoginTypeGoogle, loginTypeForOAuthProvider("google"))
	assert.Equal(t, model.LoginTypeGithub, loginTypeForOAuthProvider("github"))
	assert.Equal(t, model.LoginTypeTelegram, loginTypeForOAuthProvider("telegram"))
	assert.Equal(t, model.LoginType("custom"), loginTypeForOAuthProvider("custom"))
}

package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/config"
	"paigram/internal/model"
)

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

//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/config"
	"paigram/internal/model"
)

func TestOAuthBindFlowRejectsProviderAlreadyBoundToAnotherUser(t *testing.T) {
	provider := newIntegrationOAuthProvider(t)

	stack := newIntegrationStackWithConfig(t, func(cfg *config.Config) {
		cfg.Auth.OAuthStateTTLSeconds = 300
		cfg.Auth.DefaultOAuthRedirectURL = "https://app.example.com/auth/callback"
		cfg.Auth.AllowedOAuthProviders = []string{"github"}
		cfg.Auth.OAuthProviders = map[string]config.OAuthProviderConfig{
			"github": {
				ClientID:     provider.clientID,
				ClientSecret: provider.clientSecret,
				RedirectURL:  "https://app.example.com/auth/callback",
				AuthURL:      "https://oauth.github.test/auth",
				TokenURL:     provider.tokenURL,
				UserInfoURL:  provider.userInfoURL,
			},
		}
	})

	ownerID, _, _, _, _ := registerVerifyAndLogin(t, stack, "oauth-owner")
	_, binderAccessToken, refreshToken, _, _ := registerVerifyAndLogin(t, stack, "oauth-binder")
	binderSession := requireSessionForRefreshToken(t, stack.DB, refreshToken)
	require.NoError(t, stack.DB.Model(&model.UserSession{}).Where("id = ?", binderSession.ID).Update("created_at", time.Now().UTC()).Error)

	credential := model.UserCredential{
		UserID:            ownerID,
		Provider:          "github",
		ProviderAccountID: "github-user-123",
	}
	require.NoError(t, credential.SetAccessToken("bound-access-token"))
	require.NoError(t, credential.SetRefreshToken("bound-refresh-token"))
	require.NoError(t, stack.DB.Create(&credential).Error)

	initRes := performJSONRequest(t, stack.Router, http.MethodPut, "/api/v1/me/login-methods/github", map[string]any{
		"redirect_to": "https://app.example.com/settings/login-methods",
	}, authHeaders(binderAccessToken))
	require.Equal(t, http.StatusOK, initRes.Code, initRes.Body.String())

	initData := decodeResponseData(t, initRes)
	state, _ := initData["state"].(string)
	require.NotEmpty(t, state)

	callbackRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/oauth/github/callback", map[string]any{
		"state": state,
		"code":  "provider-code",
	}, authHeaders(binderAccessToken))
	require.Equal(t, http.StatusConflict, callbackRes.Code, callbackRes.Body.String())
	assert.Equal(t, "PROVIDER_ALREADY_BOUND", decodeErrorCode(t, callbackRes))

	var binderSessionCount int64
	require.NoError(t, stack.DB.Model(&model.UserSession{}).Where("user_id = ?", binderSession.UserID).Count(&binderSessionCount).Error)
	assert.Equal(t, int64(1), binderSessionCount)
}

func TestOAuthBindFlowRejectsReplacingExistingProviderAccountOnSameUser(t *testing.T) {
	provider := newIntegrationOAuthProvider(t)

	stack := newIntegrationStackWithConfig(t, func(cfg *config.Config) {
		cfg.Auth.OAuthStateTTLSeconds = 300
		cfg.Auth.DefaultOAuthRedirectURL = "https://app.example.com/auth/callback"
		cfg.Auth.AllowedOAuthProviders = []string{"github"}
		cfg.Auth.OAuthProviders = map[string]config.OAuthProviderConfig{
			"github": {
				ClientID:     provider.clientID,
				ClientSecret: provider.clientSecret,
				RedirectURL:  "https://app.example.com/auth/callback",
				AuthURL:      "https://oauth.github.test/auth",
				TokenURL:     provider.tokenURL,
				UserInfoURL:  provider.userInfoURL,
			},
		}
	})

	binderUserID, binderAccessToken, refreshToken, _, _ := registerVerifyAndLogin(t, stack, "oauth-binder-same-user-conflict")
	binderSession := requireSessionForRefreshToken(t, stack.DB, refreshToken)
	require.NoError(t, stack.DB.Model(&model.UserSession{}).Where("id = ?", binderSession.ID).Update("created_at", time.Now().UTC()).Error)

	credential := model.UserCredential{
		UserID:            binderUserID,
		Provider:          "github",
		ProviderAccountID: "github-user-old",
	}
	require.NoError(t, credential.SetAccessToken("bound-access-token"))
	require.NoError(t, credential.SetRefreshToken("bound-refresh-token"))
	require.NoError(t, stack.DB.Create(&credential).Error)

	initRes := performJSONRequest(t, stack.Router, http.MethodPut, "/api/v1/me/login-methods/github", map[string]any{
		"redirect_to": "https://app.example.com/settings/login-methods",
	}, authHeaders(binderAccessToken))
	require.Equal(t, http.StatusOK, initRes.Code, initRes.Body.String())

	initData := decodeResponseData(t, initRes)
	state, _ := initData["state"].(string)
	require.NotEmpty(t, state)

	callbackRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/oauth/github/callback", map[string]any{
		"state": state,
		"code":  "provider-code",
	}, authHeaders(binderAccessToken))
	require.Equal(t, http.StatusConflict, callbackRes.Code, callbackRes.Body.String())
	assert.Equal(t, "PROVIDER_REBIND_CONFLICT", decodeErrorCode(t, callbackRes))
	assert.NotContains(t, callbackRes.Body.String(), "unique")

	assertOAuthStateConsumed(t, stack, state)

	var persisted model.UserCredential
	require.NoError(t, stack.DB.Where("user_id = ? AND provider = ?", binderUserID, "github").First(&persisted).Error)
	assert.Equal(t, "github-user-old", persisted.ProviderAccountID)
}

func TestOAuthBindFlowRequiresAuthenticatedSessionForCallback(t *testing.T) {
	provider := newIntegrationOAuthProvider(t)

	stack := newIntegrationStackWithConfig(t, func(cfg *config.Config) {
		cfg.Auth.OAuthStateTTLSeconds = 300
		cfg.Auth.DefaultOAuthRedirectURL = "https://app.example.com/auth/callback"
		cfg.Auth.AllowedOAuthProviders = []string{"github"}
		cfg.Auth.OAuthProviders = map[string]config.OAuthProviderConfig{
			"github": {
				ClientID:     provider.clientID,
				ClientSecret: provider.clientSecret,
				RedirectURL:  "https://app.example.com/auth/callback",
				AuthURL:      "https://oauth.github.test/auth",
				TokenURL:     provider.tokenURL,
				UserInfoURL:  provider.userInfoURL,
			},
		}
	})

	binderUserID, binderAccessToken, _, _, _ := registerVerifyAndLogin(t, stack, "oauth-bind-callback-user")
	_, otherAccessToken, _, _, _ := registerVerifyAndLogin(t, stack, "oauth-bind-callback-other")

	initRes := performJSONRequest(t, stack.Router, http.MethodPut, "/api/v1/me/login-methods/github", map[string]any{
		"redirect_to": "https://app.example.com/settings/login-methods",
	}, authHeaders(binderAccessToken))
	require.Equal(t, http.StatusOK, initRes.Code, initRes.Body.String())

	initData := decodeResponseData(t, initRes)
	state, _ := initData["state"].(string)
	require.NotEmpty(t, state)

	noAuthRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/oauth/github/callback", map[string]any{
		"state": state,
		"code":  "provider-code",
	}, nil)
	require.Equal(t, http.StatusUnauthorized, noAuthRes.Code, noAuthRes.Body.String())
	assert.Equal(t, "UNAUTHORIZED", decodeErrorCode(t, noAuthRes))
	assertOAuthStatePresent(t, stack, state)
	assertOAuthStateOwnedByUser(t, stack, state, binderUserID)

	mismatchRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/oauth/github/callback", map[string]any{
		"state": state,
		"code":  "provider-code",
	}, authHeaders(otherAccessToken))
	require.Equal(t, http.StatusForbidden, mismatchRes.Code, mismatchRes.Body.String())
	assert.Equal(t, "FORBIDDEN", decodeErrorCode(t, mismatchRes))
	assertOAuthStatePresent(t, stack, state)
	assertOAuthStateOwnedByUser(t, stack, state, binderUserID)

	successRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/oauth/github/callback", map[string]any{
		"state": state,
		"code":  "provider-code",
	}, authHeaders(binderAccessToken))
	require.Equal(t, http.StatusOK, successRes.Code, successRes.Body.String())
	successData := decodeResponseData(t, successRes)
	assert.Equal(t, true, successData["bound"])
	assert.Equal(t, "bind_login_method", successData["purpose"])
	assertOAuthStateConsumed(t, stack, state)
}

func TestOAuthBindFlowWrongUserDoesNotConsumeState(t *testing.T) {
	provider := newIntegrationOAuthProvider(t)

	stack := newIntegrationStackWithConfig(t, func(cfg *config.Config) {
		cfg.Auth.OAuthStateTTLSeconds = 300
		cfg.Auth.DefaultOAuthRedirectURL = "https://app.example.com/auth/callback"
		cfg.Auth.AllowedOAuthProviders = []string{"github"}
		cfg.Auth.OAuthProviders = map[string]config.OAuthProviderConfig{
			"github": {
				ClientID:     provider.clientID,
				ClientSecret: provider.clientSecret,
				RedirectURL:  "https://app.example.com/auth/callback",
				AuthURL:      "https://oauth.github.test/auth",
				TokenURL:     provider.tokenURL,
				UserInfoURL:  provider.userInfoURL,
			},
		}
	})

	_, binderAccessToken, _, _, _ := registerVerifyAndLogin(t, stack, "oauth-bind-retry-user")
	_, otherAccessToken, _, _, _ := registerVerifyAndLogin(t, stack, "oauth-bind-retry-other")

	initRes := performJSONRequest(t, stack.Router, http.MethodPut, "/api/v1/me/login-methods/github", map[string]any{
		"redirect_to": "https://app.example.com/settings/login-methods",
	}, authHeaders(binderAccessToken))
	require.Equal(t, http.StatusOK, initRes.Code, initRes.Body.String())

	initData := decodeResponseData(t, initRes)
	state, _ := initData["state"].(string)
	require.NotEmpty(t, state)

	mismatchRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/oauth/github/callback", map[string]any{
		"state": state,
		"code":  "provider-code",
	}, authHeaders(otherAccessToken))
	require.Equal(t, http.StatusForbidden, mismatchRes.Code, mismatchRes.Body.String())
	assert.Equal(t, "FORBIDDEN", decodeErrorCode(t, mismatchRes))
	assertOAuthStatePresent(t, stack, state)
}

func assertOAuthStatePresent(t *testing.T, stack *integrationStack, state string) {
	t.Helper()

	var count int64
	require.NoError(t, stack.DB.Model(&model.UserOAuthState{}).Where("state = ?", state).Count(&count).Error)
	require.Equal(t, int64(1), count)
}

func assertOAuthStateConsumed(t *testing.T, stack *integrationStack, state string) {
	t.Helper()

	var count int64
	require.NoError(t, stack.DB.Model(&model.UserOAuthState{}).Where("state = ?", state).Count(&count).Error)
	require.Zero(t, count)
}

func assertOAuthStateOwnedByUser(t *testing.T, stack *integrationStack, state string, userID uint64) {
	t.Helper()

	var stateRow model.UserOAuthState
	require.NoError(t, stack.DB.Where("state = ?", state).First(&stateRow).Error)
	require.True(t, stateRow.UserID.Valid)
	require.Equal(t, int64(userID), stateRow.UserID.Int64)
}

type integrationOAuthProvider struct {
	clientID     string
	clientSecret string
	tokenURL     string
	userInfoURL  string
}

func newIntegrationOAuthProvider(t *testing.T) *integrationOAuthProvider {
	t.Helper()

	provider := &integrationOAuthProvider{
		clientID:     "123456789",
		clientSecret: "github-test-secret",
	}

	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"id":         "github-user-123",
			"name":       "GitHub Integration User",
			"login":      "integration-user",
			"avatar_url": "https://avatars.example.com/u/123",
		}))
	}))
	t.Cleanup(userInfoServer.Close)
	provider.userInfoURL = userInfoServer.URL

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte(`{"access_token":"access-token","refresh_token":"refresh-token","token_type":"Bearer","expires_in":3600,"scope":"read:user"}`))
		require.NoError(t, err)
	}))
	t.Cleanup(tokenServer.Close)
	provider.tokenURL = tokenServer.URL

	return provider
}

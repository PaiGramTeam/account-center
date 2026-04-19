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
	}, nil)
	require.Equal(t, http.StatusConflict, callbackRes.Code, callbackRes.Body.String())
	assert.Equal(t, "PROVIDER_ALREADY_BOUND", decodeErrorCode(t, callbackRes))

	var binderSessionCount int64
	require.NoError(t, stack.DB.Model(&model.UserSession{}).Where("user_id = ?", binderSession.UserID).Count(&binderSessionCount).Error)
	assert.Equal(t, int64(1), binderSessionCount)
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

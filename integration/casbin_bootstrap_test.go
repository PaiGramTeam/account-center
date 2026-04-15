//go:build integration

package integration

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"paigram/initialize"
	"paigram/internal/config"
)

func TestFreshBootstrapSeedsUsableCasbinPoliciesForDefaultAdmin(t *testing.T) {
	stack := newIntegrationStack(t)

	t.Setenv("ADMIN_EMAIL", "bootstrap-admin@example.com")
	t.Setenv("ADMIN_PASSWORD", "BootstrapPass123!")
	t.Setenv("ADMIN_NAME", "Bootstrap Admin")

	initializer := initialize.NewInitializer(stack.DB, nil, config.DatabaseConfig{AutoSeed: true})
	require.NoError(t, initializer.Run())

	loginRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "bootstrap-admin@example.com",
		"password": "BootstrapPass123!",
	}, nil)
	require.Equal(t, http.StatusOK, loginRes.Code, loginRes.Body.String())

	loginData := decodeResponseData(t, loginRes)
	accessToken := loginData["access_token"].(string)

	authoritiesRes := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/authorities", nil, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	require.Equal(t, http.StatusOK, authoritiesRes.Code, authoritiesRes.Body.String())
}

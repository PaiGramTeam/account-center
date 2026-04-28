package router

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"paigram/internal/config"
)

func TestInitializeRouterGroupsPropagatesAuthConfigToMeRouterGroup(t *testing.T) {
	engine := gin.New()
	rg := engine.Group("/api/v1")
	authCfg := config.AuthConfig{SessionFreshAgeSeconds: 7}

	InitializeRouterGroups(rg, nil, authCfg)

	require.Equal(t, authCfg, RouterGroupApp.MeRouterGroup.AuthConfig)
}

func TestPhaseTwoRouteGroupsExposeOnlyCurrentNamespaces(t *testing.T) {
	engine := gin.New()
	v1 := engine.Group("/api/v1")

	RouterGroupApp.MeRouterGroup.AuthConfig = config.AuthConfig{}
	RouterGroupApp.MeRouterGroup.Init(v1, nil)
	RouterGroupApp.AdminRouterGroup.Init(v1, nil)
	RouterGroupApp.AdminSystemRouterGroup.Init(v1, nil)
	RouterGroupApp.AdminAuditRouterGroup.Init(v1, nil)
	RouterGroupApp.PlatformBindingRouterGroup.Init(v1, nil)

	routes := map[string]struct{}{}
	for _, route := range engine.Routes() {
		routes[route.Method+" "+route.Path] = struct{}{}
	}

	require.Contains(t, routes, "GET /api/v1/me")
	require.Contains(t, routes, "PATCH /api/v1/me")
	require.Contains(t, routes, "GET /api/v1/me/dashboard-summary")
	require.Contains(t, routes, "GET /api/v1/me/emails")
	require.Contains(t, routes, "POST /api/v1/me/emails")
	require.Contains(t, routes, "DELETE /api/v1/me/emails/:emailId")
	require.Contains(t, routes, "PATCH /api/v1/me/emails/:emailId/primary")
	require.Contains(t, routes, "POST /api/v1/me/emails/:emailId/verify")
	require.Contains(t, routes, "GET /api/v1/me/login-methods")
	require.Contains(t, routes, "PATCH /api/v1/me/login-methods/:provider/primary")
	require.Contains(t, routes, "PUT /api/v1/me/login-methods/:provider")
	require.Contains(t, routes, "DELETE /api/v1/me/login-methods/:provider")
	require.Contains(t, routes, "GET /api/v1/admin/users/:id/login-methods")
	require.Contains(t, routes, "PATCH /api/v1/admin/users/:id/login-methods/:provider/primary")
	require.Contains(t, routes, "GET /api/v1/me/security/overview")
	require.Contains(t, routes, "PUT /api/v1/me/security/password")
	require.Contains(t, routes, "POST /api/v1/me/security/2fa/setup")
	require.Contains(t, routes, "POST /api/v1/me/security/2fa/confirm")
	require.Contains(t, routes, "DELETE /api/v1/me/security/2fa")
	require.Contains(t, routes, "POST /api/v1/me/security/2fa/backup-codes/regenerate")
	require.Contains(t, routes, "GET /api/v1/me/sessions")
	require.Contains(t, routes, "DELETE /api/v1/me/sessions/:sessionId")
	require.Contains(t, routes, "GET /api/v1/me/activity-logs")
	require.Contains(t, routes, "GET /api/v1/admin/audit-logs")
	require.Contains(t, routes, "GET /api/v1/admin/audit-logs/:id")
	require.Contains(t, routes, "GET /api/v1/admin/system/settings/site")
	require.Contains(t, routes, "PATCH /api/v1/admin/system/settings/site")
	require.Contains(t, routes, "GET /api/v1/admin/system/settings/registration")
	require.Contains(t, routes, "PATCH /api/v1/admin/system/settings/registration")
	require.Contains(t, routes, "GET /api/v1/admin/system/settings/email")
	require.Contains(t, routes, "PATCH /api/v1/admin/system/settings/email")
	require.Contains(t, routes, "GET /api/v1/admin/system/settings/legal")
	require.Contains(t, routes, "PATCH /api/v1/admin/system/settings/legal")
	require.Contains(t, routes, "GET /api/v1/admin/system/auth-controls")
	require.Contains(t, routes, "PATCH /api/v1/admin/system/auth-controls")
	require.Contains(t, routes, "PUT /api/v1/me/platform-accounts/:bindingId/credential")
	require.Contains(t, routes, "POST /api/v1/me/platform-accounts/:bindingId/refresh")
	require.Contains(t, routes, "GET /api/v1/me/platform-accounts/:bindingId/runtime-summary")
	require.NotContains(t, routes, "GET /api/v1/me/platform-accounts/:bindingId/summary")
	require.Contains(t, routes, "PUT /api/v1/admin/platform-accounts/:bindingId/credential")
	require.Contains(t, routes, "GET /api/v1/admin/platform-accounts/:bindingId/runtime-summary")
	require.NotContains(t, routes, "GET /api/v1/profiles/:id")
	require.NotContains(t, routes, "PATCH /api/v1/profiles/:id")
	require.NotContains(t, routes, "GET /api/v1/profiles/:id/accounts")
	require.NotContains(t, routes, "POST /api/v1/profiles/:id/accounts/bind")
	require.NotContains(t, routes, "DELETE /api/v1/profiles/:id/accounts/:provider")
	require.NotContains(t, routes, "POST /api/v1/profiles/:id/emails")
	require.NotContains(t, routes, "DELETE /api/v1/profiles/:id/emails/:email")
	require.NotContains(t, routes, "PATCH /api/v1/profiles/:id/emails/:email/primary")
	require.NotContains(t, routes, "POST /api/v1/profiles/:id/emails/:email/verify")
	require.NotContains(t, routes, "POST /api/v1/profiles/:id/password/change")
	require.NotContains(t, routes, "POST /api/v1/profiles/:id/2fa/enable")
	require.NotContains(t, routes, "POST /api/v1/profiles/:id/2fa/confirm")
	require.NotContains(t, routes, "POST /api/v1/profiles/:id/2fa/disable")
	require.NotContains(t, routes, "POST /api/v1/profiles/:id/2fa/regenerate-backup-codes")
	require.NotContains(t, routes, "GET /api/v1/profiles/:id/devices")
	require.NotContains(t, routes, "DELETE /api/v1/profiles/:id/devices/:device_id")
	require.NotContains(t, routes, "GET /api/v1/sessions")
	require.NotContains(t, routes, "DELETE /api/v1/sessions/:id")
	require.NotContains(t, routes, "GET /api/v1/users")
	require.NotContains(t, routes, "GET /api/v1/roles")
	require.NotContains(t, routes, "GET /api/v1/authorities")
	require.NotContains(t, routes, "GET /api/v1/casbin/authorities/:id/policies")
}

func TestPhaseTwoAdminRoutesHideLegacyNamespaces(t *testing.T) {
	engine := gin.New()
	v1 := engine.Group("/api/v1")

	RouterGroupApp.AdminRouterGroup.Init(v1, nil)
	RouterGroupApp.AdminSystemRouterGroup.Init(v1, nil)

	routes := map[string]struct{}{}
	for _, route := range engine.Routes() {
		routes[route.Method+" "+route.Path] = struct{}{}
	}

	require.Contains(t, routes, "GET /api/v1/admin/users")
	require.Contains(t, routes, "GET /api/v1/admin/roles")
	require.Contains(t, routes, "GET /api/v1/admin/system/platform-services")
	require.NotContains(t, routes, "GET /api/v1/users")
	require.NotContains(t, routes, "GET /api/v1/roles")
	require.NotContains(t, routes, "GET /api/v1/authorities")
	require.NotContains(t, routes, "GET /api/v1/casbin/authorities/:id/policies")
	require.NotContains(t, routes, "GET /api/v1/platform-services")
}

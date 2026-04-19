//go:build integration

package integration

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPhaseTwoPublicRouteShape(t *testing.T) {
	stack := newIntegrationStack(t)

	for _, tc := range []struct {
		method string
		path   string
		code   int
	}{
		{method: http.MethodGet, path: "/api/v1/me", code: http.StatusUnauthorized},
		{method: http.MethodGet, path: "/api/v1/me/sessions", code: http.StatusUnauthorized},
		{method: http.MethodGet, path: "/api/v1/admin/system/platform-services", code: http.StatusUnauthorized},
		{method: http.MethodGet, path: "/api/v1/admin/audit-logs", code: http.StatusUnauthorized},
		{method: http.MethodGet, path: "/api/v1/admin/system/settings/site", code: http.StatusUnauthorized},
		{method: http.MethodGet, path: "/api/v1/admin/system/auth-controls", code: http.StatusUnauthorized},
		{method: http.MethodPut, path: "/api/v1/me/login-methods/github", code: http.StatusUnauthorized},
		{method: http.MethodGet, path: "/api/v1/bot-authorizations", code: http.StatusNotFound},
		{method: http.MethodPost, path: "/api/v1/bot-authorizations", code: http.StatusNotFound},
		{method: http.MethodGet, path: "/api/v1/bot-authorizations/1", code: http.StatusNotFound},
		{method: http.MethodDelete, path: "/api/v1/bot-authorizations/1", code: http.StatusNotFound},
		{method: http.MethodGet, path: "/api/v1/profiles/1", code: http.StatusNotFound},
		{method: http.MethodGet, path: "/api/v1/profiles/1/accounts", code: http.StatusNotFound},
		{method: http.MethodPost, path: "/api/v1/profiles/1/accounts/bind", code: http.StatusNotFound},
		{method: http.MethodDelete, path: "/api/v1/profiles/1/accounts/github", code: http.StatusNotFound},
		{method: http.MethodPost, path: "/api/v1/profiles/1/emails", code: http.StatusNotFound},
		{method: http.MethodDelete, path: "/api/v1/profiles/1/emails/user@example.com", code: http.StatusNotFound},
		{method: http.MethodPatch, path: "/api/v1/profiles/1/emails/user@example.com/primary", code: http.StatusNotFound},
		{method: http.MethodPost, path: "/api/v1/profiles/1/emails/user@example.com/verify", code: http.StatusNotFound},
		{method: http.MethodPost, path: "/api/v1/profiles/1/password/change", code: http.StatusNotFound},
		{method: http.MethodPost, path: "/api/v1/profiles/1/2fa/enable", code: http.StatusNotFound},
		{method: http.MethodPost, path: "/api/v1/profiles/1/2fa/confirm", code: http.StatusNotFound},
		{method: http.MethodPost, path: "/api/v1/profiles/1/2fa/disable", code: http.StatusNotFound},
		{method: http.MethodPost, path: "/api/v1/profiles/1/2fa/regenerate-backup-codes", code: http.StatusNotFound},
		{method: http.MethodGet, path: "/api/v1/profiles/1/devices", code: http.StatusNotFound},
		{method: http.MethodDelete, path: "/api/v1/profiles/1/devices/device-1", code: http.StatusNotFound},
		{method: http.MethodGet, path: "/api/v1/sessions", code: http.StatusNotFound},
		{method: http.MethodDelete, path: "/api/v1/sessions/1", code: http.StatusNotFound},
		{method: http.MethodGet, path: "/api/v1/platform-services", code: http.StatusNotFound},
	} {
		resp := performJSONRequest(t, stack.Router, tc.method, tc.path, nil, nil)
		require.Equal(t, tc.code, resp.Code, "%s %s", tc.method, tc.path)
	}

	t.Run("authenticated non-admin cannot access admin platform service routes", func(t *testing.T) {
		_, accessToken, _, _, _ := registerVerifyAndLogin(t, stack, "phase-two-platform-non-admin")

		resp := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/admin/system/platform-services", nil, authHeaders(accessToken))

		require.Equal(t, http.StatusForbidden, resp.Code, resp.Body.String())
	})
}

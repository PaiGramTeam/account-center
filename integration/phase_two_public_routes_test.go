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
		{method: http.MethodGet, path: "/api/v1/profiles/1", code: http.StatusNotFound},
		{method: http.MethodGet, path: "/api/v1/sessions", code: http.StatusNotFound},
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

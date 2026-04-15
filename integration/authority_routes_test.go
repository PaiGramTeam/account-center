//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/casbin"
)

func TestAuthorityRoutesRegistered(t *testing.T) {
	stack := newIntegrationStack(t)

	// Test that authority routes are registered
	t.Run("GET /api/v1/authorities returns 401 without auth", func(t *testing.T) {
		w := performJSONRequest(t, stack.Router, "GET", "/api/v1/authorities", nil, nil)

		// Should return 401 Unauthorized (not 404 Not Found)
		assert.Equal(t, http.StatusUnauthorized, w.Code,
			"Authority routes should be registered and require authentication")
	})

	t.Run("POST /api/v1/authorities returns 401 without auth", func(t *testing.T) {
		w := performJSONRequest(t, stack.Router, "POST", "/api/v1/authorities", nil, nil)

		// Should return 401 Unauthorized (not 404 Not Found)
		assert.Equal(t, http.StatusUnauthorized, w.Code,
			"Authority routes should be registered and require authentication")
	})

	t.Run("GET /api/v1/authorities/:id returns 401 without auth", func(t *testing.T) {
		w := performJSONRequest(t, stack.Router, "GET", "/api/v1/authorities/1", nil, nil)

		// Should return 401 Unauthorized (not 404 Not Found)
		assert.Equal(t, http.StatusUnauthorized, w.Code,
			"Authority routes should be registered and require authentication")
	})

	t.Run("PUT /api/v1/authorities/:id returns 401 without auth", func(t *testing.T) {
		w := performJSONRequest(t, stack.Router, "PUT", "/api/v1/authorities/1", nil, nil)

		// Should return 401 Unauthorized (not 404 Not Found)
		assert.Equal(t, http.StatusUnauthorized, w.Code,
			"Authority routes should be registered and require authentication")
	})

	t.Run("DELETE /api/v1/authorities/:id returns 401 without auth", func(t *testing.T) {
		w := performJSONRequest(t, stack.Router, "DELETE", "/api/v1/authorities/1", nil, nil)

		// Should return 401 Unauthorized (not 404 Not Found)
		assert.Equal(t, http.StatusUnauthorized, w.Code,
			"Authority routes should be registered and require authentication")
	})

	t.Run("POST /api/v1/authorities/:id/permissions returns 401 without auth", func(t *testing.T) {
		w := performJSONRequest(t, stack.Router, "POST", "/api/v1/authorities/1/permissions", nil, nil)

		// Should return 401 Unauthorized (not 404 Not Found)
		assert.Equal(t, http.StatusUnauthorized, w.Code,
			"Authority routes should be registered and require authentication")
	})

	t.Run("GET /api/v1/authorities/:id/permissions returns 401 without auth", func(t *testing.T) {
		w := performJSONRequest(t, stack.Router, "GET", "/api/v1/authorities/1/permissions", nil, nil)

		// Should return 401 Unauthorized (not 404 Not Found)
		assert.Equal(t, http.StatusUnauthorized, w.Code,
			"Authority routes should be registered and require authentication")
	})

	t.Run("PUT /api/v1/casbin/authorities/:id/policies returns 401 without auth", func(t *testing.T) {
		w := performJSONRequest(t, stack.Router, "PUT", "/api/v1/casbin/authorities/1/policies", nil, nil)

		// Should return 401 Unauthorized (not 404 Not Found)
		assert.Equal(t, http.StatusUnauthorized, w.Code,
			"Dedicated casbin routes should be registered and require authentication")
	})

	t.Run("GET /api/v1/casbin/authorities/:id/policies returns 401 without auth", func(t *testing.T) {
		w := performJSONRequest(t, stack.Router, "GET", "/api/v1/casbin/authorities/1/policies", nil, nil)

		// Should return 401 Unauthorized (not 404 Not Found)
		assert.Equal(t, http.StatusUnauthorized, w.Code,
			"Dedicated casbin routes should be registered and require authentication")
	})

	t.Run("POST /api/v1/authorities/:id/casbin-policies returns 404", func(t *testing.T) {
		w := performJSONRequest(t, stack.Router, "POST", "/api/v1/authorities/1/casbin-policies", nil, nil)

		assert.Equal(t, http.StatusNotFound, w.Code,
			"Legacy casbin policy routes should no longer be registered")
	})

	t.Run("GET /api/v1/authorities/:id/casbin-policies returns 404", func(t *testing.T) {
		w := performJSONRequest(t, stack.Router, "GET", "/api/v1/authorities/1/casbin-policies", nil, nil)

		assert.Equal(t, http.StatusNotFound, w.Code,
			"Legacy casbin policy routes should no longer be registered")
	})

	t.Run("GET /api/v1/casbin/authorities/:id/policies returns 200 for admin and 403 for moderator", func(t *testing.T) {
		seed := seedAuthorityTestData(t, stack, casbin.GetEnforcer())

		adminResp := performJSONRequest(t, stack.Router, http.MethodGet,
			"/api/v1/casbin/authorities/1/policies", nil, authHeaders(seed.adminToken))
		require.Equal(t, http.StatusOK, adminResp.Code, adminResp.Body.String())

		moderatorResp := performJSONRequest(t, stack.Router, http.MethodPut,
			"/api/v1/casbin/authorities/1/policies", map[string]any{
				"policies": []map[string]any{{
					"path":   "/api/v1/users",
					"method": "GET",
				}},
			}, authHeaders(seed.moderatorToken))
		assert.Equal(t, http.StatusForbidden, moderatorResp.Code, moderatorResp.Body.String())
	})

	t.Run("Casbin policy routes still require admin role even with direct custom grant", func(t *testing.T) {
		isolatedStack := newIntegrationStack(t)
		casbin.Reset()
		enforcer, err := casbin.InitEnforcer(isolatedStack.DB)
		require.NoError(t, err)
		seed := seedAuthorityTestData(t, isolatedStack, enforcer)

		moderatorRoleIDStr := fmt.Sprint(seed.moderatorRole.ID)
		_, err = casbin.GetEnforcer().AddPolicy(moderatorRoleIDStr, "/api/v1/casbin/authorities/:id/policies", "PUT")
		require.NoError(t, err)
		require.NoError(t, casbin.GetEnforcer().LoadPolicy())

		resp := performJSONRequest(t, isolatedStack.Router, http.MethodPut,
			"/api/v1/casbin/authorities/1/policies", map[string]any{
				"policies": []map[string]any{{
					"path":   "/api/v1/users",
					"method": "GET",
				}},
			}, authHeaders(seed.moderatorToken))

		assert.Equal(t, http.StatusForbidden, resp.Code, resp.Body.String())
	})
}

package admin

import (
	"fmt"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestAdminRouterRegistersManagementRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	v1 := engine.Group("/api/v1")

	routerGroup := RouterGroup{}
	routerGroup.Init(v1, nil)

	routes := engine.Routes()
	registered := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		registered[fmt.Sprintf("%s %s", route.Method, route.Path)] = struct{}{}
	}

	for _, route := range []string{
		"GET /api/v1/admin/users",
		"POST /api/v1/admin/users",
		"GET /api/v1/admin/users/:id",
		"GET /api/v1/admin/users/:id/login-methods",
		"PATCH /api/v1/admin/users/:id",
		"PATCH /api/v1/admin/users/:id/login-methods/:provider/primary",
		"PATCH /api/v1/admin/users/:id/status",
		"POST /api/v1/admin/users/:id/reset-password",
		"GET /api/v1/admin/users/:id/audit-logs",
		"GET /api/v1/admin/users/:id/roles",
		"PUT /api/v1/admin/users/:id/roles",
		"PATCH /api/v1/admin/users/:id/primary-role",
		"GET /api/v1/admin/users/:id/permissions",
		"GET /api/v1/admin/users/:id/sessions",
		"DELETE /api/v1/admin/users/:id/sessions/:sessionId",
		"GET /api/v1/admin/users/:id/security-summary",
		"GET /api/v1/admin/users/:id/login-logs",
		"GET /api/v1/admin/roles",
		"POST /api/v1/admin/roles",
		"GET /api/v1/admin/roles/:id",
		"PUT /api/v1/admin/roles/:id",
		"PATCH /api/v1/admin/roles/:id",
		"DELETE /api/v1/admin/roles/:id",
		"GET /api/v1/admin/roles/:id/users",
		"PUT /api/v1/admin/roles/:id/users",
		"GET /api/v1/admin/roles/:id/permissions",
		"PUT /api/v1/admin/roles/:id/permissions",
	} {
		_, ok := registered[route]
		assert.True(t, ok, "expected admin route %s to be registered", route)
	}

	_, hasLegacyPost := registered["POST /api/v1/admin/roles/:id/permissions"]
	assert.False(t, hasLegacyPost, "did not expect legacy POST admin permission route")

	_, hasLegacyUserRolePost := registered["POST /api/v1/admin/users/:id/roles"]
	assert.False(t, hasLegacyUserRolePost, "did not expect legacy POST admin user-role route")
	_, hasLegacyUserRoleDelete := registered["DELETE /api/v1/admin/users/:id/roles/:roleId"]
	assert.False(t, hasLegacyUserRoleDelete, "did not expect legacy DELETE admin user-role route")
}

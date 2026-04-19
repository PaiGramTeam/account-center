package userrole

import (
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRegisterRoutesExposesOnlyReadContracts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	NewHandler(nil).RegisterRoutes(engine.Group("/api/v1/admin/users"))

	routes := map[string]struct{}{}
	for _, route := range engine.Routes() {
		routes[route.Method+" "+route.Path] = struct{}{}
	}

	_, hasGetRoles := routes["GET /api/v1/admin/users/:id/roles"]
	assert.True(t, hasGetRoles)
	_, hasGetPermissions := routes["GET /api/v1/admin/users/:id/permissions"]
	assert.True(t, hasGetPermissions)
	_, hasPostRoles := routes["POST /api/v1/admin/users/:id/roles"]
	assert.False(t, hasPostRoles)
	_, hasDeleteRole := routes["DELETE /api/v1/admin/users/:id/roles/:roleId"]
	assert.False(t, hasDeleteRole)
}

func TestHandlerDoesNotExposeLegacyMutationMethods(t *testing.T) {
	handlerType := reflect.TypeOf(&Handler{})
	_, hasAssign := handlerType.MethodByName("AssignRoleToUser")
	assert.False(t, hasAssign)
	_, hasRemove := handlerType.MethodByName("RemoveRoleFromUser")
	assert.False(t, hasRemove)
}

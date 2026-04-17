package platformbinding

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRouterGroupInitRegistersPlatformBindingRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	api := r.Group("/api/v1")

	rg := &RouterGroup{}
	assert.NotPanics(t, func() {
		rg.Init(api, nil)
	})

	routes := r.Routes()
	routeCounts := make(map[string]int, len(routes))
	for _, route := range routes {
		routeCounts[route.Method+" "+route.Path]++
	}

	assert.Equal(t, 1, routeCounts["GET /api/v1/me/platform-accounts"])
	assert.Equal(t, 1, routeCounts["POST /api/v1/me/platform-accounts"])
	assert.Equal(t, 1, routeCounts["GET /api/v1/me/platform-accounts/:bindingId"])
	assert.Equal(t, 1, routeCounts["PATCH /api/v1/me/platform-accounts/:bindingId"])
	assert.Equal(t, 1, routeCounts["PATCH /api/v1/me/platform-accounts/:bindingId/primary-profile"])
	assert.Equal(t, 1, routeCounts["DELETE /api/v1/me/platform-accounts/:bindingId"])
	assert.Equal(t, 1, routeCounts["GET /api/v1/me/platform-accounts/:bindingId/profiles"])
	assert.Equal(t, 1, routeCounts["GET /api/v1/me/platform-accounts/:bindingId/consumer-grants"])
	assert.Equal(t, 1, routeCounts["PUT /api/v1/me/platform-accounts/:bindingId/consumer-grants/:consumer"])
	assert.Equal(t, 1, routeCounts["GET /api/v1/admin/platform-accounts"])
	assert.Equal(t, 1, routeCounts["GET /api/v1/admin/platform-accounts/:bindingId"])
	assert.Equal(t, 1, routeCounts["GET /api/v1/admin/platform-accounts/:bindingId/profiles"])
	assert.Equal(t, 1, routeCounts["GET /api/v1/admin/platform-accounts/:bindingId/consumer-grants"])
	assert.Equal(t, 1, routeCounts["PUT /api/v1/admin/platform-accounts/:bindingId/consumer-grants/:consumer"])
	assert.Equal(t, 1, routeCounts["POST /api/v1/admin/platform-accounts/:bindingId/refresh"])
	assert.Equal(t, 1, routeCounts["DELETE /api/v1/admin/platform-accounts/:bindingId"])
}

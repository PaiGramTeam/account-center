package platform

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRouterGroupInitRegistersPlatformRoutes(t *testing.T) {
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

	assert.Equal(t, 1, routeCounts["GET /api/v1/me/platforms"])
	assert.Equal(t, 1, routeCounts["GET /api/v1/me/platforms/:platform/schema"])
	assert.Zero(t, routeCounts["GET /api/v1/me/platform-accounts/:bindingId/summary"])
	assert.Zero(t, routeCounts["GET /api/v1/platform-services"])
	assert.Zero(t, routeCounts["GET /api/v1/platform-services/:id"])
	assert.Zero(t, routeCounts["POST /api/v1/platform-services"])
	assert.Zero(t, routeCounts["PATCH /api/v1/platform-services/:id"])
	assert.Zero(t, routeCounts["DELETE /api/v1/platform-services/:id"])
	assert.Zero(t, routeCounts["POST /api/v1/platform-services/:id/check"])
}

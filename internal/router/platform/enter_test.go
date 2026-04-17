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
	assert.Equal(t, 1, routeCounts["GET /api/v1/me/platform-accounts/:refId/summary"])
	assert.Equal(t, 1, routeCounts["GET /api/v1/platform-services"])
	assert.Equal(t, 1, routeCounts["GET /api/v1/platform-services/:id"])
	assert.Equal(t, 1, routeCounts["POST /api/v1/platform-services"])
	assert.Equal(t, 1, routeCounts["PATCH /api/v1/platform-services/:id"])
	assert.Equal(t, 1, routeCounts["DELETE /api/v1/platform-services/:id"])
	assert.Equal(t, 1, routeCounts["POST /api/v1/platform-services/:id/check"])
}

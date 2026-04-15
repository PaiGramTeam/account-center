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
	registered := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		registered[route.Method+" "+route.Path] = struct{}{}
	}

	_, ok := registered["GET /api/v1/me/platforms"]
	assert.True(t, ok)
	_, ok = registered["GET /api/v1/me/platforms/:platform/schema"]
	assert.True(t, ok)
}

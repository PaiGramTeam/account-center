//go:build integration

package integration

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/middleware"
)

func TestRedisRateLimitStoreBlocksExceededRequests(t *testing.T) {
	env := loadIntegrationEnv(t)
	redisClient := openRedis(t, env)
	defer func() { _ = redisClient.Close() }()

	prefix := uniqueRedisPrefix(t.Name(), env.RedisPrefix)
	cleanupRedisPrefix(t, redisClient, prefix)
	defer cleanupRedisPrefix(t, redisClient, prefix)

	store, err := middleware.NewRedisStore(redisClient, prefix)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.RateLimit(middleware.RateLimitConfig{
		Rate:    "2-M",
		KeyFunc: middleware.IPKeyFunc,
		Store:   store,
	}))
	r.GET("/limited", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/limited", nil)
		req.RemoteAddr = "1.1.1.1:12345"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	blockedReq := httptest.NewRequest(http.MethodGet, "/limited", nil)
	blockedReq.RemoteAddr = "1.1.1.1:12345"
	blockedRes := httptest.NewRecorder()
	r.ServeHTTP(blockedRes, blockedReq)
	assert.Equal(t, http.StatusTooManyRequests, blockedRes.Code)
	assert.NotEmpty(t, blockedRes.Header().Get("Retry-After"))

	newIPReq := httptest.NewRequest(http.MethodGet, "/limited", nil)
	newIPReq.RemoteAddr = "2.2.2.2:12345"
	newIPRes := httptest.NewRecorder()
	r.ServeHTTP(newIPRes, newIPReq)
	assert.Equal(t, http.StatusOK, newIPRes.Code)
}

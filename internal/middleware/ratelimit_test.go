package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

func TestRateLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create an in-memory store for testing
	store := memory.NewStore()

	t.Run("allows requests within limit", func(t *testing.T) {
		router := gin.New()
		router.Use(RateLimit(RateLimitConfig{
			Rate:    "5-M", // 5 requests per minute
			KeyFunc: IPKeyFunc,
			Store:   store,
		}))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "ok"})
		})

		// Make 5 requests - all should succeed
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)
			assert.NotEmpty(t, w.Header().Get("X-RateLimit-Limit"))
			assert.NotEmpty(t, w.Header().Get("X-RateLimit-Remaining"))
			assert.NotEmpty(t, w.Header().Get("X-RateLimit-Reset"))
		}
	})

	t.Run("blocks requests exceeding limit", func(t *testing.T) {
		// Create a new store for this test
		testStore := memory.NewStore()

		router := gin.New()
		router.Use(RateLimit(RateLimitConfig{
			Rate:    "3-M", // 3 requests per minute
			KeyFunc: IPKeyFunc,
			Store:   testStore,
		}))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "ok"})
		})

		// Make 3 requests - should succeed
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)
		}

		// 4th request should be blocked
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.NotEmpty(t, w.Header().Get("Retry-After"))
	})

	t.Run("rate limits by IP", func(t *testing.T) {
		testStore := memory.NewStore()

		router := gin.New()
		router.Use(RateLimit(RateLimitConfig{
			Rate:    "2-M",
			KeyFunc: IPKeyFunc,
			Store:   testStore,
		}))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "ok"})
		})

		// Make 2 requests from IP 1.1.1.1 - should succeed
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "1.1.1.1:12345"
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// 3rd request from same IP should be blocked
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "1.1.1.1:12345"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)

		// Request from different IP should succeed
		req = httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "2.2.2.2:12345"
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("rate limits by user ID", func(t *testing.T) {
		testStore := memory.NewStore()

		router := gin.New()
		// Middleware to set user_id in context
		router.Use(func(c *gin.Context) {
			userID := c.GetHeader("X-User-ID")
			if userID != "" {
				c.Set("user_id", userID)
			}
			c.Next()
		})
		router.Use(RateLimit(RateLimitConfig{
			Rate:    "2-M",
			KeyFunc: UserIDKeyFunc,
			Store:   testStore,
		}))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "ok"})
		})

		// Make 2 requests from user 123 - should succeed
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("X-User-ID", "123")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// 3rd request from same user should be blocked
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-User-ID", "123")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)

		// Request from different user should succeed
		req = httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-User-ID", "456")
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestIPKeyFunc(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.RemoteAddr = "192.168.1.1:12345"

	key := IPKeyFunc(c)
	assert.Equal(t, "192.168.1.1", key)
}

func TestUserIDKeyFunc(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("with user ID in context", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Request.RemoteAddr = "192.168.1.1:12345"
		c.Set("user_id", uint64(123))

		key := UserIDKeyFunc(c)
		assert.Equal(t, "user:123", key)
	})

	t.Run("without user ID in context", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Request.RemoteAddr = "192.168.1.1:12345"

		key := UserIDKeyFunc(c)
		// Should fallback to IP
		assert.Equal(t, "192.168.1.1", key)
	})
}

func TestEmailKeyFunc(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("extracts email from query parameter", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("GET", "/test?email=test@example.com", nil)
		c.Request.RemoteAddr = "192.168.1.1:12345"

		keyFunc := EmailKeyFunc("email")
		key := keyFunc(c)
		assert.Equal(t, "email:test@example.com", key)
	})

	t.Run("fallback to IP when email not found", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Request.RemoteAddr = "192.168.1.1:12345"

		keyFunc := EmailKeyFunc("email")
		key := keyFunc(c)
		assert.Equal(t, "192.168.1.1", key)
	})
}

func TestNewRedisStore(t *testing.T) {
	// This test would require an actual Redis connection
	// Skip for now as it's an integration test
	t.Skip("Requires Redis connection")
}

func TestRateLimitConfig_InvalidRate(t *testing.T) {
	gin.SetMode(gin.TestMode)

	require.Panics(t, func() {
		store := memory.NewStore()
		router := gin.New()
		router.Use(RateLimit(RateLimitConfig{
			Rate:    "invalid", // Invalid rate format
			KeyFunc: IPKeyFunc,
			Store:   store,
		}))
	}, "Should panic on invalid rate format")
}

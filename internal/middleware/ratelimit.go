package middleware

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	redisClient "github.com/redis/go-redis/v9"
	"github.com/ulule/limiter/v3"
	mgin "github.com/ulule/limiter/v3/drivers/middleware/gin"
	"github.com/ulule/limiter/v3/drivers/store/redis"

	"paigram/internal/response"
)

// RateLimitConfig holds configuration for rate limiting.
type RateLimitConfig struct {
	// Rate is the rate limit in format "requests-period" (e.g., "5-M", "100-H", "1000-D")
	// M = per minute, H = per hour, D = per day
	Rate string

	// KeyFunc generates the rate limit key from the request
	KeyFunc KeyFunc

	// Store is the limiter store (usually Redis)
	Store limiter.Store
}

// KeyFunc is a function that generates a rate limit key from the gin context.
type KeyFunc func(*gin.Context) string

// IPKeyFunc returns a KeyFunc that uses the client IP address as the rate limit key.
// It respects custom IP headers (e.g., CF-Connecting-IP) if configured via REAL_IP_HEADER env var.
// Otherwise, it uses Gin's ClientIP() which respects TrustedProxies configuration.
func IPKeyFunc(c *gin.Context) string {
	// Check for custom IP header (e.g., Cloudflare's CF-Connecting-IP)
	if customHeader := os.Getenv("REAL_IP_HEADER"); customHeader != "" {
		if ip := c.GetHeader(customHeader); ip != "" {
			return ip
		}
	}

	// Fallback to Gin's ClientIP which respects TrustedProxies
	// SECURITY: Ensure TrustedProxies is configured in router to prevent IP spoofing
	return c.ClientIP()
}

// UserIDKeyFunc returns a KeyFunc that uses the authenticated user ID as the rate limit key.
// This requires the AuthMiddleware to be applied first.
func UserIDKeyFunc(c *gin.Context) string {
	userID, exists := c.Get("user_id")
	if !exists {
		// Fallback to IP if user ID is not available
		return c.ClientIP()
	}
	return fmt.Sprintf("user:%v", userID)
}

// EmailKeyFunc returns a KeyFunc that extracts the email from the request body.
// The field parameter specifies the JSON field name to extract.
func EmailKeyFunc(field string) KeyFunc {
	return func(c *gin.Context) string {
		// Try to get email from query parameter first
		if email := c.Query(field); email != "" {
			return fmt.Sprintf("email:%s", email)
		}
		// Try to get from form data
		if email := c.PostForm(field); email != "" {
			return fmt.Sprintf("email:%s", email)
		}
		// Fallback to IP if email extraction fails
		return c.ClientIP()
	}
}

// RateLimit creates a rate limiting middleware with the given configuration.
func RateLimit(config RateLimitConfig) gin.HandlerFunc {
	// Parse rate string
	rate, err := limiter.NewRateFromFormatted(config.Rate)
	if err != nil {
		panic(fmt.Sprintf("invalid rate format: %s", config.Rate))
	}

	// Create limiter instance
	instance := limiter.New(config.Store, rate)

	// Create middleware with custom key function
	middleware := mgin.NewMiddleware(instance, mgin.WithKeyGetter(func(c *gin.Context) string {
		return config.KeyFunc(c)
	}))

	return func(c *gin.Context) {
		// Call the limiter middleware
		middleware(c)

		// Check if request was aborted (rate limit exceeded)
		if c.IsAborted() {
			// Get the rate limit context to extract retry-after
			key := config.KeyFunc(c)
			context, err := instance.Get(c.Request.Context(), key)
			if err == nil {
				// Calculate retry-after in seconds
				retryAfter := context.Reset - time.Now().Unix()
				if retryAfter < 0 {
					retryAfter = 0
				}

				// Set Retry-After header
				c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))

				// Return error response with retry_after in details
				response.TooManyRequestsWithCode(c, "RATE_LIMIT_EXCEEDED", "rate limit exceeded", map[string]interface{}{
					"retry_after": retryAfter,
				})
			} else {
				// Fallback if we can't get the context
				response.TooManyRequestsWithCode(c, "RATE_LIMIT_EXCEEDED", "rate limit exceeded", nil)
			}
			return
		}

		c.Next()
	}
}

// NewRedisStore creates a new Redis-based rate limit store.
func NewRedisStore(client *redisClient.Client, prefix string) (limiter.Store, error) {
	return redis.NewStoreWithOptions(client, limiter.StoreOptions{
		Prefix:   prefix,
		MaxRetry: 3,
	})
}

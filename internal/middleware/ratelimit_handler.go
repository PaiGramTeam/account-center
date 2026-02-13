package middleware

import (
	"github.com/gin-gonic/gin"
	"paigram/internal/response"
)

// RateLimitStatsHandler returns a handler that exposes rate limiting statistics
// This should be protected with admin authentication
func RateLimitStatsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		stats := GetRateLimitStats()
		response.Success(c, stats)
	}
}

// RateLimitStatsResetHandler returns a handler that resets rate limiting statistics
// This should be protected with admin authentication
func RateLimitStatsResetHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		ResetRateLimitStats()
		response.Success(c, gin.H{
			"message": "rate limit statistics reset successfully",
		})
	}
}

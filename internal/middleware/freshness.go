package middleware

import (
	"time"

	"github.com/gin-gonic/gin"

	"paigram/internal/config"
	"paigram/internal/response"
	"paigram/internal/service"
)

// RequireFreshSession creates middleware that ensures the session is "fresh"
// A fresh session is one that was created recently (within freshAge)
// This is used for sensitive operations like password changes, 2FA setup, etc.
func RequireFreshSession(authCfg config.AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get session ID from context (set by AuthMiddleware)
		sessionIDRaw, exists := c.Get("session_id")
		if !exists {
			response.UnauthorizedWithCode(c, "SESSION_NOT_FOUND", "session not found", nil)
			c.Abort()
			return
		}

		sessionID, ok := sessionIDRaw.(uint64)
		if !ok || sessionID == 0 {
			response.UnauthorizedWithCode(c, "INVALID_SESSION", "invalid session", nil)
			c.Abort()
			return
		}

		// Get session from database via MiddlewareService
		middlewareService := &service.ServiceGroupApp.UserServiceGroup.MiddlewareService
		sessionPtr, err := middlewareService.GetSessionByID(sessionID)
		if err != nil {
			response.InternalServerErrorWithCode(c, "SESSION_ERROR", "failed to validate session", nil)
			c.Abort()
			return
		}
		if sessionPtr == nil {
			response.UnauthorizedWithCode(c, "SESSION_NOT_FOUND", "session not found", nil)
			c.Abort()
			return
		}
		session := *sessionPtr

		// Check session freshness based on CreatedAt
		freshAge := time.Duration(authCfg.SessionFreshAgeSeconds) * time.Second
		if freshAge <= 0 {
			freshAge = 24 * time.Hour // Default: 1 day (same as better-auth)
		}

		sessionAge := time.Since(session.CreatedAt)
		if sessionAge > freshAge {
			response.ForbiddenWithCode(c, "SESSION_NOT_FRESH",
				"this operation requires a fresh session, please re-authenticate",
				gin.H{
					"session_age_seconds": int(sessionAge.Seconds()),
					"fresh_age_seconds":   int(freshAge.Seconds()),
					"requires_reauth":     true,
				})
			c.Abort()
			return
		}

		// Session is fresh, continue
		c.Next()
	}
}

// OptionalFreshSession is similar to RequireFreshSession but doesn't abort
// It sets a context flag indicating whether the session is fresh
func OptionalFreshSession(authCfg config.AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionIDRaw, exists := c.Get("session_id")
		if !exists {
			c.Set("session_is_fresh", false)
			c.Next()
			return
		}

		sessionID, ok := sessionIDRaw.(uint64)
		if !ok || sessionID == 0 {
			c.Set("session_is_fresh", false)
			c.Next()
			return
		}

		// Get session from database via MiddlewareService
		middlewareService := &service.ServiceGroupApp.UserServiceGroup.MiddlewareService
		sessionPtr, err := middlewareService.GetSessionByID(sessionID)
		if err != nil || sessionPtr == nil {
			c.Set("session_is_fresh", false)
			c.Next()
			return
		}

		// Check session freshness based on CreatedAt
		freshAge := time.Duration(authCfg.SessionFreshAgeSeconds) * time.Second
		if freshAge <= 0 {
			freshAge = 24 * time.Hour
		}

		isFresh := time.Since(sessionPtr.CreatedAt) <= freshAge
		c.Set("session_is_fresh", isFresh)

		c.Next()
	}
}

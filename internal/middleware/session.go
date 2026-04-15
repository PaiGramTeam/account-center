package middleware

import (
	"time"

	"github.com/gin-gonic/gin"

	"paigram/internal/response"
	"paigram/internal/service"
)

// SessionValidation middleware validates that the current session is still valid
// This middleware should be used after AuthMiddleware
func SessionValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get session ID from context (set by AuthMiddleware)
		sessionIDVal, exists := c.Get("session_id")
		if !exists {
			response.UnauthorizedWithCode(c, "NO_SESSION", "no session found", nil)
			c.Abort()
			return
		}

		sessionID, ok := sessionIDVal.(uint64)
		if !ok || sessionID == 0 {
			response.UnauthorizedWithCode(c, "INVALID_SESSION", "invalid session ID", nil)
			c.Abort()
			return
		}

		// Reload session from database via MiddlewareService
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

		now := time.Now().UTC()

		// Check if session is revoked
		if session.RevokedAt.Valid {
			response.UnauthorizedWithCode(c, "SESSION_REVOKED", "session has been revoked", map[string]string{
				"reason": session.RevokedReason,
			})
			c.Abort()
			return
		}

		// Check if access token is expired
		if session.AccessExpiry.Before(now) {
			response.UnauthorizedWithCode(c, "SESSION_EXPIRED", "session has expired", map[string]string{
				"expired_at": session.AccessExpiry.Format(time.RFC3339),
			})
			c.Abort()
			return
		}

		// Validate user ID matches
		userID, _ := GetUserID(c)
		if session.UserID != userID {
			response.UnauthorizedWithCode(c, "SESSION_INVALID", "session validation failed", nil)
			c.Abort()
			return
		}

		// Session is valid, continue
		c.Next()
	}
}

// RefreshSessionActivity updates the last active time for the session
// This middleware should be used after AuthMiddleware
// TODO: Requires MiddlewareService.UpdateSessionLastActivity to work - currently non-functional
func RefreshSessionActivity() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Need MiddlewareService.UpdateSessionLastActivity(sessionID, time) to update activity
		// Skipping session activity update for now
		c.Next()
	}
}

// GetSessionID retrieves the session ID from context
func GetSessionID(c *gin.Context) (uint64, bool) {
	sessionIDVal, exists := c.Get("session_id")
	if !exists {
		return 0, false
	}

	sessionID, ok := sessionIDVal.(uint64)
	return sessionID, ok
}

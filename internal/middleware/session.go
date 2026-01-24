package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"paigram/internal/logging"
	"paigram/internal/model"
	"paigram/internal/response"
)

// SessionValidation middleware validates that the current session is still valid
// This middleware should be used after AuthMiddleware
func SessionValidation(db *gorm.DB) gin.HandlerFunc {
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

		// Reload session from database to ensure it's still valid
		var session model.UserSession
		if err := db.First(&session, sessionID).Error; err != nil {
			logging.Error("failed to load session",
				zap.Error(err),
				zap.Uint64("session_id", sessionID),
			)
			response.UnauthorizedWithCode(c, "SESSION_NOT_FOUND", "session not found", nil)
			c.Abort()
			return
		}

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

		// Validate user still exists and is active
		userID, _ := GetUserID(c)
		if session.UserID != userID {
			logging.Warn("session user ID mismatch",
				zap.Uint64("session_user_id", session.UserID),
				zap.Uint64("context_user_id", userID),
			)
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
func RefreshSessionActivity(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get session ID from context
		sessionIDVal, exists := c.Get("session_id")
		if !exists {
			c.Next()
			return
		}

		sessionID, ok := sessionIDVal.(uint64)
		if !ok || sessionID == 0 {
			c.Next()
			return
		}

		// Update last activity timestamp in background (non-blocking)
		go func() {
			now := time.Now().UTC()
			if err := db.Model(&model.UserSession{}).
				Where("id = ?", sessionID).
				Update("updated_at", now).Error; err != nil {
				logging.Warn("failed to update session activity",
					zap.Error(err),
					zap.Uint64("session_id", sessionID),
				)
			}
		}()

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

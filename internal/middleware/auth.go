package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/model"
	"paigram/internal/response"
	"paigram/internal/sessioncache"
)

// hashToken creates SHA-256 hash of token for database lookup
func hashToken(token string) string {
	if token == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// AuthMiddleware creates middleware that validates access tokens and sets user ID in context.
// It also implements automatic session refresh when updateAge threshold is reached.
func AuthMiddleware(db *gorm.DB, sessionCache sessioncache.Store, authCfg config.AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			response.UnauthorizedWithCode(c, "MISSING_TOKEN", "authorization header required", nil)
			c.Abort()
			return
		}

		// Check if it's a Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			response.UnauthorizedWithCode(c, "INVALID_TOKEN_FORMAT", "authorization header must be Bearer token", nil)
			c.Abort()
			return
		}

		accessToken := parts[1]
		if accessToken == "" {
			response.UnauthorizedWithCode(c, "EMPTY_TOKEN", "access token cannot be empty", nil)
			c.Abort()
			return
		}

		ctx := context.Background()

		// Check if token is revoked (in cache)
		revoked, err := sessionCache.IsRevoked(ctx, sessioncache.TokenTypeAccess, accessToken)
		if err != nil && !errors.Is(err, redis.Nil) {
			// Cache check failed, continue to database check
		} else if revoked {
			response.UnauthorizedWithCode(c, "TOKEN_REVOKED", "access token has been revoked", nil)
			c.Abort()
			return
		}

		// Try to get complete session data from cache first (fast path - no DB query!)
		var session model.UserSession
		var userID uint64
		var needDBLookup = true

		sessionData, err := sessionCache.GetSessionData(ctx, sessioncache.TokenTypeAccess, accessToken)
		if err == nil && sessionData != nil {
			// Cache hit! Validate using cached data
			now := time.Now().UTC()

			// Check expiry from cache
			if sessionData.AccessExpiry.Before(now) {
				response.UnauthorizedWithCode(c, "TOKEN_EXPIRED", "access token has expired", nil)
				c.Abort()
				return
			}

			// Check revocation from cache
			if sessionData.RevokedAt != nil {
				response.UnauthorizedWithCode(c, "SESSION_REVOKED", "session has been revoked", nil)
				c.Abort()
				return
			}

			// Cache validation passed - populate session for later use
			session.ID = sessionData.SessionID
			session.UserID = sessionData.UserID
			session.AccessExpiry = sessionData.AccessExpiry
			session.RefreshExpiry = sessionData.RefreshExpiry
			if sessionData.RevokedAt != nil {
				session.RevokedAt.Valid = true
				session.RevokedAt.Time = *sessionData.RevokedAt
			}

			userID = sessionData.UserID
			needDBLookup = false

			log.Printf("[auth] cache hit for user %d, skipped DB query", userID)
		}

		// If not in cache, fall back to database lookup
		if needDBLookup {
			accessTokenHash := hashToken(accessToken)
			if err := db.Where("access_token_hash = ?", accessTokenHash).First(&session).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					response.UnauthorizedWithCode(c, "INVALID_TOKEN", "invalid access token", nil)
				} else {
					response.InternalServerErrorWithCode(c, "AUTH_ERROR", "authentication failed", nil)
				}
				c.Abort()
				return
			}
			userID = session.UserID

			// Validate session from DB
			now := time.Now().UTC()

			if session.AccessExpiry.Before(now) {
				response.UnauthorizedWithCode(c, "TOKEN_EXPIRED", "access token has expired", nil)
				c.Abort()
				return
			}

			if session.RevokedAt.Valid {
				response.UnauthorizedWithCode(c, "SESSION_REVOKED", "session has been revoked", nil)
				c.Abort()
				return
			}

			log.Printf("[auth] cache miss for user %d, queried database", userID)
		}

		// Verify user exists and is active
		var user model.User
		if err := db.First(&user, userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				response.UnauthorizedWithCode(c, "USER_NOT_FOUND", "user not found", nil)
			} else {
				response.InternalServerErrorWithCode(c, "AUTH_ERROR", "authentication failed", nil)
			}
			c.Abort()
			return
		}

		// Check if user is active
		if user.Status != model.UserStatusActive {
			response.UnauthorizedWithCode(c, "USER_INACTIVE", "user account is not active", nil)
			c.Abort()
			return
		}

		// Auto-refresh session if updateAge threshold is reached
		// This extends session lifetime without requiring explicit refresh token call
		updateAge := time.Duration(authCfg.SessionUpdateAgeSeconds) * time.Second
		if updateAge <= 0 {
			updateAge = 24 * time.Hour // Default to 1 day like better-auth
		}

		now := time.Now().UTC()
		sessionAge := now.Sub(session.UpdatedAt)
		if sessionAge >= updateAge {
			// Time to refresh the session expiry
			refreshTTL := time.Duration(authCfg.RefreshTokenTTLSeconds) * time.Second
			if refreshTTL <= 0 {
				refreshTTL = 7 * 24 * time.Hour // Default 7 days
			}

			newExpiry := now.Add(refreshTTL)

			// Update session expiry asynchronously to avoid blocking the request
			go func(sessionID uint64, expiry time.Time) {
				if err := db.Model(&model.UserSession{}).
					Where("id = ?", sessionID).
					Updates(map[string]interface{}{
						"refresh_expiry": expiry,
						"updated_at":     now,
					}).Error; err != nil {
					log.Printf("[auth] failed to auto-refresh session %d: %v", sessionID, err)
				} else {
					log.Printf("[auth] auto-refreshed session %d, new expiry: %s", sessionID, expiry.Format(time.RFC3339))
				}
			}(session.ID, newExpiry)
		}

		// Set user ID in context for downstream handlers
		SetUserID(c, userID)

		// Also set session ID for potential use
		c.Set("session_id", session.ID)

		c.Next()
	}
}

// OptionalAuthMiddleware is similar to AuthMiddleware but does not abort on missing/invalid tokens.
// It sets the user ID in context if a valid token is provided, otherwise continues without authentication.
func OptionalAuthMiddleware(db *gorm.DB, sessionCache sessioncache.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.Next()
			return
		}

		accessToken := parts[1]
		if accessToken == "" {
			c.Next()
			return
		}

		ctx := context.Background()

		// Try to get session from cache or database
		var session model.UserSession
		sessionID, err := sessionCache.GetSessionID(ctx, sessioncache.TokenTypeAccess, accessToken)
		if err == nil && sessionID > 0 {
			db.First(&session, sessionID)
		} else {
			// Query by token hash
			accessTokenHash := hashToken(accessToken)
			db.Where("access_token_hash = ?", accessTokenHash).First(&session)
		}

		// If valid session found, set user ID
		if session.ID > 0 {
			now := time.Now().UTC()
			if !session.AccessExpiry.Before(now) && !session.RevokedAt.Valid {
				var user model.User
				if err := db.First(&user, session.UserID).Error; err == nil {
					if user.Status == model.UserStatusActive {
						SetUserID(c, session.UserID)
						c.Set("session_id", session.ID)
					}
				}
			}
		}

		c.Next()
	}
}

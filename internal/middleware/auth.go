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

	"paigram/internal/config"
	"paigram/internal/model"
	"paigram/internal/response"
	"paigram/internal/service"
	"paigram/internal/sessioncache"
	"paigram/internal/utils/secsubtle"
)

const defaultSessionUpdateAge = 24 * time.Hour

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
func AuthMiddleware(sessionCache sessioncache.Store, authCfg config.AuthConfig) gin.HandlerFunc {
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
		accessTokenHash := hashToken(accessToken)

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
				log.Printf("[auth] cached access expiry reached for token, falling back to database validation")
			} else {
				if _, err := sessionCache.Get(ctx, sessioncache.RevokedSessionMarkerKey(sessionData.SessionID)); err == nil {
					response.UnauthorizedWithCode(c, "SESSION_REVOKED", "session has been revoked", nil)
					c.Abort()
					return
				} else if err != nil && !errors.Is(err, redis.Nil) {
					log.Printf("[auth] failed to read revoked session marker for session %d: %v", sessionData.SessionID, err)
				}

				currentAccessHash, err := sessionCache.Get(ctx, sessioncache.CurrentAccessTokenHashKey(sessionData.SessionID))
				if err == nil {
					if !secsubtle.StringEqual(string(currentAccessHash), accessTokenHash) {
						log.Printf("[auth] cached access token hash mismatch for session %d, falling back to database validation", sessionData.SessionID)
					} else {
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
				} else if errors.Is(err, redis.Nil) {
					log.Printf("[auth] missing current access token hash marker for session %d, falling back to database validation", sessionData.SessionID)
				} else {
					log.Printf("[auth] failed to read current access token hash marker for session %d: %v", sessionData.SessionID, err)
				}
			}
		}

		// If not in cache, fall back to database lookup
		if needDBLookup {
			middlewareService := &service.ServiceGroupApp.UserServiceGroup.MiddlewareService
			sessionPtr, err := middlewareService.GetSessionByAccessToken(accessTokenHash)
			if err != nil {
				response.InternalServerErrorWithCode(c, "AUTH_ERROR", "authentication failed", nil)
				c.Abort()
				return
			}
			if sessionPtr == nil {
				response.UnauthorizedWithCode(c, "INVALID_TOKEN", "invalid access token", nil)
				c.Abort()
				return
			}
			session = *sessionPtr
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
		middlewareService := &service.ServiceGroupApp.UserServiceGroup.MiddlewareService
		userPtr, err := middlewareService.GetUserByID(userID)
		if err != nil {
			response.InternalServerErrorWithCode(c, "AUTH_ERROR", "authentication failed", nil)
			c.Abort()
			return
		}
		if userPtr == nil {
			response.UnauthorizedWithCode(c, "USER_NOT_FOUND", "user not found", nil)
			c.Abort()
			return
		}
		user := *userPtr

		// Check if user is active
		if user.Status != model.UserStatusActive {
			response.UnauthorizedWithCode(c, "USER_INACTIVE", "user account is not active", nil)
			c.Abort()
			return
		}

		updateAge := time.Duration(authCfg.SessionUpdateAgeSeconds) * time.Second
		if updateAge <= 0 {
			updateAge = defaultSessionUpdateAge
		}

		sessionForRefresh := session
		if !needDBLookup {
			freshSession, err := middlewareService.GetSessionByID(session.ID)
			if err != nil {
				log.Printf("[auth] failed to load session %d for refresh check: %v", session.ID, err)
			} else if freshSession != nil {
				sessionForRefresh = *freshSession
			}
		}

		if time.Since(sessionForRefresh.UpdatedAt) >= updateAge {
			now := time.Now().UTC()

			accessTTL := time.Duration(authCfg.AccessTokenTTLSeconds) * time.Second
			if accessTTL <= 0 {
				accessTTL = 15 * time.Minute
			}

			refreshTTL := time.Duration(authCfg.RefreshTokenTTLSeconds) * time.Second
			if refreshTTL <= 0 {
				refreshTTL = 7 * 24 * time.Hour
			}

			if err := middlewareService.UpdateSessionExpiry(sessionForRefresh.ID, now.Add(accessTTL), now.Add(refreshTTL), now); err != nil {
				log.Printf("[auth] failed to refresh session %d expiry: %v", sessionForRefresh.ID, err)
			}
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
func OptionalAuthMiddleware(sessionCache sessioncache.Store) gin.HandlerFunc {
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

		middlewareService := &service.ServiceGroupApp.UserServiceGroup.MiddlewareService

		// Try to get session from cache or database
		var session model.UserSession
		sessionID, err := sessionCache.GetSessionID(ctx, sessioncache.TokenTypeAccess, accessToken)
		if err == nil && sessionID > 0 {
			sessionPtr, _ := middlewareService.GetSessionByAccessToken(hashToken(accessToken))
			if sessionPtr != nil {
				session = *sessionPtr
			}
		} else {
			// Query by token hash
			accessTokenHash := hashToken(accessToken)
			sessionPtr, _ := middlewareService.GetSessionByAccessToken(accessTokenHash)
			if sessionPtr != nil {
				session = *sessionPtr
			}
		}

		// If valid session found, set user ID
		if session.ID > 0 {
			now := time.Now().UTC()
			if !session.AccessExpiry.Before(now) && !session.RevokedAt.Valid {
				userPtr, err := middlewareService.GetUserByID(session.UserID)
				if err == nil && userPtr != nil {
					if userPtr.Status == model.UserStatusActive {
						SetUserID(c, session.UserID)
						c.Set("session_id", session.ID)
					}
				}
			}
		}

		c.Next()
	}
}

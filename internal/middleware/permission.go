package middleware

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"paigram/internal/permission"
	"paigram/internal/response"
)

const (
	// ContextKeyUserID is the key for storing user ID in gin context.
	ContextKeyUserID = "user_id"
)

// PermissionMiddleware creates middleware that checks if the user has required permissions.
func PermissionMiddleware(permMgr *permission.Manager, requiredPerms ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := getUserIDFromContext(c)
		if userID == 0 {
			response.Unauthorized(c, "authentication required")
			c.Abort()
			return
		}

		for _, perm := range requiredPerms {
			has, err := permMgr.HasPermission(userID, perm)
			if err != nil {
				response.InternalServerError(c, "permission check failed")
				c.Abort()
				return
			}

			if !has {
				response.Forbidden(c, "insufficient permissions")
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// RoleMiddleware creates middleware that checks if the user has required roles.
func RoleMiddleware(permMgr *permission.Manager, requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := getUserIDFromContext(c)
		if userID == 0 {
			response.Unauthorized(c, "authentication required")
			c.Abort()
			return
		}

		for _, role := range requiredRoles {
			has, err := permMgr.HasRole(userID, role)
			if err != nil {
				response.InternalServerError(c, "role check failed")
				c.Abort()
				return
			}

			if !has {
				response.Forbidden(c, "insufficient permissions")
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// AnyRoleMiddleware creates middleware that checks if the user has any of the required roles.
func AnyRoleMiddleware(permMgr *permission.Manager, requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := getUserIDFromContext(c)
		if userID == 0 {
			response.Unauthorized(c, "authentication required")
			c.Abort()
			return
		}

		has, err := permMgr.HasAnyRole(userID, requiredRoles)
		if err != nil {
			response.InternalServerError(c, "role check failed")
			c.Abort()
			return
		}

		if !has {
			response.Forbidden(c, "insufficient permissions")
			c.Abort()
			return
		}

		c.Next()
	}
}

// AdminMiddleware creates middleware that checks if the user is an admin.
func AdminMiddleware(permMgr *permission.Manager) gin.HandlerFunc {
	return RoleMiddleware(permMgr, "admin")
}

// getUserIDFromContext extracts the user ID from the gin context.
func getUserIDFromContext(c *gin.Context) uint64 {
	// Try to get from context first
	if val, exists := c.Get(ContextKeyUserID); exists {
		if userID, ok := val.(uint64); ok {
			return userID
		}
	}

	// Try from header or query parameter as fallback
	userIDStr := c.GetHeader("X-User-ID")
	if userIDStr == "" {
		userIDStr = c.Query("user_id")
	}

	if userIDStr != "" {
		if userID, err := strconv.ParseUint(userIDStr, 10, 64); err == nil {
			return userID
		}
	}

	return 0
}

// SetUserID sets the user ID in the gin context.
func SetUserID(c *gin.Context, userID uint64) {
	c.Set(ContextKeyUserID, userID)
}

// GetUserID retrieves the user ID from the gin context.
func GetUserID(c *gin.Context) (uint64, bool) {
	val, exists := c.Get(ContextKeyUserID)
	if !exists {
		return 0, false
	}

	userID, ok := val.(uint64)
	return userID, ok
}

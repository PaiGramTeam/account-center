package middleware

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"

	"paigram/internal/casbin"
	"paigram/internal/response"
	"paigram/internal/service"
)

const (
	// ContextKeyUserID is the key for storing user ID in gin context.
	ContextKeyUserID = "user_id"
)

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

// SelfOrCasbinPermission allows access if user is accessing their own resource OR has Casbin permission.
// This is useful for routes like /profiles/:id where users can view/edit their own profiles,
// but admins with appropriate permissions can access any profile.
func SelfOrCasbinPermission() gin.HandlerFunc {
	return func(c *gin.Context) {
		currentUserID, exists := GetUserID(c)
		if !exists {
			response.Unauthorized(c, "user not authenticated")
			c.Abort()
			return
		}

		// Parse target user ID from path parameter
		targetUserIDStr := c.Param("id")
		targetUserID, err := strconv.ParseUint(targetUserIDStr, 10, 64)
		if err != nil {
			response.BadRequest(c, "invalid user ID")
			c.Abort()
			return
		}

		// Allow if accessing own resource
		if currentUserID == targetUserID {
			c.Next()
			return
		}

		// Otherwise check Casbin permission
		path := c.Request.URL.Path
		method := c.Request.Method

		enforcer := casbin.GetEnforcer()
		if enforcer == nil {
			response.InternalServerError(c, "permission system unavailable")
			c.Abort()
			return
		}

		// Get user's roles
		middlewareService := &service.ServiceGroupApp.UserServiceGroup.MiddlewareService
		roleIDs, err := middlewareService.GetUserRoles(currentUserID)
		if err != nil {
			response.InternalServerError(c, "failed to get user roles")
			c.Abort()
			return
		}

		// Check permission with each role
		hasPermission := false
		for _, roleID := range roleIDs {
			ok, err := enforcer.Enforce(fmt.Sprint(roleID), path, method)
			if err != nil {
				continue
			}
			if ok {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			response.ForbiddenWithCode(c, "FORBIDDEN", "insufficient permissions", nil)
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireSelf creates middleware that only allows users to operate on their own resources.
func RequireSelf() gin.HandlerFunc {
	return func(c *gin.Context) {
		currentUserID, exists := GetUserID(c)
		if !exists {
			response.UnauthorizedWithCode(c, "UNAUTHORIZED", "user not authenticated", nil)
			c.Abort()
			return
		}

		targetUserID, err := strconv.ParseUint(c.Param("id"), 10, 64)
		if err != nil {
			response.BadRequestWithCode(c, "INVALID_USER_ID", "invalid user ID", nil)
			c.Abort()
			return
		}

		if currentUserID != targetUserID {
			response.ForbiddenWithCode(c, "FORBIDDEN", "can only manage your own resources", nil)
			c.Abort()
			return
		}

		c.Next()
	}
}

// CasbinMiddleware checks API access permissions using Casbin enforcer.
// It retrieves user roles from database and checks each role against the requested path and method.
func CasbinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := GetUserID(c)
		if !exists {
			response.Unauthorized(c, "user not authenticated")
			c.Abort()
			return
		}

		path := c.Request.URL.Path
		method := c.Request.Method

		enforcer := casbin.GetEnforcer()
		if enforcer == nil {
			response.InternalServerError(c, "permission system unavailable")
			c.Abort()
			return
		}

		// Get user's roles from database
		middlewareService := &service.ServiceGroupApp.UserServiceGroup.MiddlewareService
		roleIDs, err := middlewareService.GetUserRoles(userID)
		if err != nil {
			response.InternalServerError(c, "failed to get user roles")
			c.Abort()
			return
		}

		if len(roleIDs) == 0 {
			response.ForbiddenWithCode(c, "FORBIDDEN", "insufficient permissions", nil)
			c.Abort()
			return
		}

		// Check permission with each role - allow if ANY role grants access
		hasPermission := false
		for _, roleID := range roleIDs {
			ok, err := enforcer.Enforce(fmt.Sprint(roleID), path, method)
			if err != nil {
				// Log error but continue checking other roles
				continue
			}
			if ok {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			response.ForbiddenWithCode(c, "FORBIDDEN", "insufficient permissions", nil)
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireRoleMiddleware creates middleware that requires user to have any of the specified roles.
func RequireRoleMiddleware(roleNames ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := GetUserID(c)
		if !exists {
			response.Unauthorized(c, "user not authenticated")
			c.Abort()
			return
		}

		middlewareService := &service.ServiceGroupApp.UserServiceGroup.MiddlewareService
		has, err := middlewareService.HasAnyRole(userID, roleNames)
		if err != nil {
			response.InternalServerError(c, "role check failed")
			c.Abort()
			return
		}

		if !has {
			response.ForbiddenWithCode(c, "FORBIDDEN", "insufficient role permissions", nil)
			c.Abort()
			return
		}

		c.Next()
	}
}

// AdminOnlyMiddleware requires user to have admin role.
func AdminOnlyMiddleware() gin.HandlerFunc {
	return RequireRoleMiddleware("admin")
}

package user

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/handler"
	"paigram/internal/middleware"
)

// RouterGroup holds user-related routers.
type RouterGroup struct{}

// Init registers user routes on the provided router group.
func (r *RouterGroup) Init(rg *gin.RouterGroup, db *gorm.DB) {
	// Get user handler from global API group
	userHandler := &handler.ApiGroupApp.UserApiGroup.Handler

	// User management routes
	users := rg.Group("/users")
	{
		// List users - requires user:read permission
		users.GET("", middleware.CasbinMiddleware(), userHandler.ListUsers)

		// Create user - requires user:write permission
		users.POST("", middleware.CasbinMiddleware(), userHandler.CreateUser)

		// Get user - self or requires user:read permission
		users.GET("/:id", middleware.SelfOrCasbinPermission(), userHandler.GetUser)

		// Update user - self or requires user:write permission
		users.PATCH("/:id", middleware.SelfOrCasbinPermission(), userHandler.UpdateUser)

		// Delete user - requires user:write permission
		users.DELETE("/:id", middleware.CasbinMiddleware(), userHandler.DeleteUser)

		// Update user status - requires user:write permission
		users.PATCH("/:id/status", middleware.CasbinMiddleware(), userHandler.UpdateUserStatus)

		// Reset user password - requires user:write permission
		users.POST("/:id/reset-password", middleware.CasbinMiddleware(), userHandler.ResetUserPassword)

		// Get audit logs - self or requires audit:read permission
		users.GET("/:id/audit-logs", middleware.SelfOrCasbinPermission(), userHandler.GetAuditLogs)

		// Get user roles - self or requires role:read permission
		users.GET("/:id/roles", middleware.SelfOrCasbinPermission(), userHandler.GetUserRoles)

		// Get user permissions - self or requires permission:read permission
		users.GET("/:id/permissions", middleware.SelfOrCasbinPermission(), userHandler.GetUserPermissions)

		// Get user sessions - self or requires user:manage permission
		users.GET("/:id/sessions", middleware.SelfOrCasbinPermission(), userHandler.GetUserSessions)

		// Revoke a user session - self or requires user:manage permission
		users.DELETE("/:id/sessions/:sessionId", middleware.SelfOrCasbinPermission(), userHandler.RevokeUserSession)

		// Get user security summary - self or requires user:read permission
		users.GET("/:id/security-summary", middleware.SelfOrCasbinPermission(), userHandler.GetSecuritySummary)
	}

	// Login log routes (under /users path)
	userHandler.RegisterLoginLogRoutes(rg.Group("/users"))
}

package user

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/handler"
	"paigram/internal/middleware"
	"paigram/internal/model"
	"paigram/internal/permission"
)

// RouterGroup holds user-related routers.
type RouterGroup struct{}

// Init registers user routes on the provided router group.
func (r *RouterGroup) Init(rg *gin.RouterGroup, db *gorm.DB, permMgr *permission.Manager) {
	// Get user handler from global API group
	userHandler := &handler.ApiGroupApp.UserApiGroup.Handler

	// User management routes
	users := rg.Group("/users")
	{
		// List users - requires user:read permission
		users.GET("", middleware.PermissionMiddleware(permMgr, model.PermUserRead), userHandler.ListUsers)

		// Create user - requires user:write permission
		users.POST("", middleware.PermissionMiddleware(permMgr, model.PermUserWrite), userHandler.CreateUser)

		// Get user - self or requires user:read permission
		users.GET("/:id", middleware.SelfOrPermission(permMgr, model.PermUserRead), userHandler.GetUser)

		// Update user - self or requires user:write permission
		users.PATCH("/:id", middleware.SelfOrPermission(permMgr, model.PermUserWrite), userHandler.UpdateUser)

		// Delete user - requires user:delete permission
		users.DELETE("/:id", middleware.PermissionMiddleware(permMgr, model.PermUserDelete), userHandler.DeleteUser)

		// Update user status - requires admin role
		users.PATCH("/:id/status", middleware.AdminMiddleware(permMgr), userHandler.UpdateUserStatus)

		// Reset user password - requires admin role
		users.POST("/:id/reset-password", middleware.AdminMiddleware(permMgr), userHandler.ResetUserPassword)

		// Get audit logs - self or requires audit:read permission
		users.GET("/:id/audit-logs", middleware.SelfOrPermission(permMgr, model.PermAuditRead), userHandler.GetAuditLogs)

		// Get user roles - self or requires role:read permission
		users.GET("/:id/roles", middleware.SelfOrPermission(permMgr, model.PermRoleRead), userHandler.GetUserRoles)

		// Get user permissions - self or requires permission:read permission
		users.GET("/:id/permissions", middleware.SelfOrPermission(permMgr, model.PermPermissionRead), userHandler.GetUserPermissions)

		// Get user sessions - self or requires user:manage permission
		users.GET("/:id/sessions", middleware.SelfOrPermission(permMgr, model.PermUserManage), userHandler.GetUserSessions)

		// Revoke a user session - self or requires user:manage permission
		users.DELETE("/:id/sessions/:sessionId", middleware.SelfOrPermission(permMgr, model.PermUserManage), userHandler.RevokeUserSession)

		// Get user security summary - self or requires user:read permission
		users.GET("/:id/security-summary", middleware.SelfOrPermission(permMgr, model.PermUserRead), userHandler.GetSecuritySummary)
	}

	// Login log routes (under /users path)
	userHandler.RegisterLoginLogRoutes(rg.Group("/users"))
}

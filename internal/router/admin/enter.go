package admin

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/handler"
	"paigram/internal/middleware"
)

// RouterGroup holds admin management routers.
type RouterGroup struct{}

// Init registers /admin management routes on the provided router group.
func (r *RouterGroup) Init(rg *gin.RouterGroup, _ *gorm.DB) {
	adminOnly := middleware.AdminOnlyMiddleware()
	userHandler := &handler.ApiGroupApp.UserApiGroup.Handler
	users := rg.Group("/admin/users")
	{
		users.GET("", adminOnly, userHandler.ListUsers)
		users.POST("", adminOnly, userHandler.CreateUser)
		users.GET("/:id", adminOnly, userHandler.GetUser)
		users.PATCH("/:id", adminOnly, userHandler.UpdateUser)
		users.DELETE("/:id", adminOnly, userHandler.DeleteUser)
		users.PATCH("/:id/status", adminOnly, userHandler.UpdateUserStatus)
		users.POST("/:id/reset-password", adminOnly, userHandler.ResetUserPassword)
		users.GET("/:id/audit-logs", adminOnly, userHandler.GetAuditLogs)
		users.GET("/:id/roles", adminOnly, userHandler.GetUserRoles)
		users.PUT("/:id/roles", adminOnly, userHandler.PutUserRoles)
		users.PATCH("/:id/primary-role", adminOnly, userHandler.PatchPrimaryRole)
		users.GET("/:id/permissions", adminOnly, userHandler.GetUserPermissions)
		users.GET("/:id/sessions", adminOnly, userHandler.GetUserSessions)
		users.DELETE("/:id/sessions/:sessionId", adminOnly, userHandler.RevokeUserSession)
		users.GET("/:id/security-summary", adminOnly, userHandler.GetSecuritySummary)
		users.GET("/:id/login-logs", adminOnly, userHandler.GetLoginLogs)
	}

	authorityHandler := &handler.ApiGroupApp.AuthorityApiGroup.AuthorityHandler
	roles := rg.Group("/admin/roles")
	{
		roles.POST("", adminOnly, authorityHandler.CreateAuthority)
		roles.GET("", adminOnly, authorityHandler.ListAuthorities)
		roles.GET("/:id", adminOnly, authorityHandler.GetAuthority)
		roles.PUT("/:id", adminOnly, authorityHandler.UpdateAuthority)
		roles.PATCH("/:id", adminOnly, authorityHandler.UpdateAuthority)
		roles.DELETE("/:id", adminOnly, authorityHandler.DeleteAuthority)
		roles.GET("/:id/users", adminOnly, authorityHandler.GetAuthorityUsers)
		roles.PUT("/:id/users", adminOnly, authorityHandler.ReplaceAuthorityUsers)
		roles.POST("/:id/permissions", adminOnly, authorityHandler.AssignPermissions)
		roles.GET("/:id/permissions", adminOnly, authorityHandler.GetRolePermissions)
	}
}

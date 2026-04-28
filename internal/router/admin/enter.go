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
	adminGate := middleware.RequireRoleMiddleware("admin")
	permissionCheck := middleware.CasbinMiddleware()
	userHandler := &handler.ApiGroupApp.UserApiGroup.Handler
	users := rg.Group("/admin/users")
	users.Use(adminGate)
	{
		users.GET("", permissionCheck, userHandler.ListUsers)
		users.POST("", permissionCheck, userHandler.CreateUser)
		users.GET("/:id", permissionCheck, userHandler.GetUser)
		users.GET("/:id/login-methods", permissionCheck, userHandler.ListUserLoginMethods)
		users.PATCH("/:id", permissionCheck, userHandler.UpdateUser)
		users.PATCH("/:id/login-methods/:provider/primary", permissionCheck, userHandler.PatchUserPrimaryLoginMethod)
		users.DELETE("/:id", permissionCheck, userHandler.DeleteUser)
		users.PATCH("/:id/status", permissionCheck, userHandler.UpdateUserStatus)
		users.POST("/:id/reset-password", permissionCheck, userHandler.ResetUserPassword)
		users.GET("/:id/audit-logs", permissionCheck, userHandler.GetAuditLogs)
		users.GET("/:id/roles", permissionCheck, userHandler.GetUserRoles)
		users.PUT("/:id/roles", permissionCheck, userHandler.PutUserRoles)
		users.PATCH("/:id/primary-role", permissionCheck, userHandler.PatchPrimaryRole)
		users.GET("/:id/permissions", permissionCheck, userHandler.GetUserPermissions)
		users.GET("/:id/sessions", permissionCheck, userHandler.GetUserSessions)
		users.DELETE("/:id/sessions/:sessionId", permissionCheck, userHandler.RevokeUserSession)
		users.GET("/:id/security-summary", permissionCheck, userHandler.GetSecuritySummary)
		users.GET("/:id/login-logs", permissionCheck, userHandler.GetLoginLogs)
	}

	authorityHandler := &handler.ApiGroupApp.AuthorityApiGroup.AuthorityHandler
	roles := rg.Group("/admin/roles")
	roles.Use(adminGate)
	{
		roles.POST("", permissionCheck, authorityHandler.CreateAuthority)
		roles.GET("", permissionCheck, authorityHandler.ListAuthorities)
		roles.GET("/:id", permissionCheck, authorityHandler.GetAuthority)
		roles.PUT("/:id", permissionCheck, authorityHandler.UpdateAuthority)
		roles.PATCH("/:id", permissionCheck, authorityHandler.UpdateAuthority)
		roles.DELETE("/:id", permissionCheck, authorityHandler.DeleteAuthority)
		roles.GET("/:id/users", permissionCheck, authorityHandler.GetAuthorityUsers)
		roles.PUT("/:id/users", permissionCheck, authorityHandler.ReplaceAuthorityUsers)
		roles.PUT("/:id/permissions", permissionCheck, authorityHandler.AssignPermissions)
		roles.GET("/:id/permissions", permissionCheck, authorityHandler.GetRolePermissions)
	}
}

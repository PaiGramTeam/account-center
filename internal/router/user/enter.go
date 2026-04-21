package user

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// RouterGroup holds user-related routers.
type RouterGroup struct{}

// Init no longer registers public user management routes.
func (r *RouterGroup) Init(_ *gin.RouterGroup, _ *gorm.DB) {
}

type userRouteAccess struct {
	List                     gin.HandlerFunc
	Create                   gin.HandlerFunc
	Read                     gin.HandlerFunc
	LoginMethods             gin.HandlerFunc
	Update                   gin.HandlerFunc
	UpdatePrimaryLoginMethod gin.HandlerFunc
	Delete                   gin.HandlerFunc
	UpdateStatus             gin.HandlerFunc
	ResetPassword            gin.HandlerFunc
	AuditLogs                gin.HandlerFunc
	Roles                    gin.HandlerFunc
	Permissions              gin.HandlerFunc
	Sessions                 gin.HandlerFunc
	RevokeSession            gin.HandlerFunc
	SecuritySummary          gin.HandlerFunc
	LoginLogs                gin.HandlerFunc
}

type userRouteHandler interface {
	ListUsers(*gin.Context)
	CreateUser(*gin.Context)
	GetUser(*gin.Context)
	ListUserLoginMethods(*gin.Context)
	UpdateUser(*gin.Context)
	PatchUserPrimaryLoginMethod(*gin.Context)
	DeleteUser(*gin.Context)
	UpdateUserStatus(*gin.Context)
	ResetUserPassword(*gin.Context)
	GetAuditLogs(*gin.Context)
	GetUserRoles(*gin.Context)
	GetUserPermissions(*gin.Context)
	GetUserSessions(*gin.Context)
	RevokeUserSession(*gin.Context)
	GetSecuritySummary(*gin.Context)
	GetLoginLogs(*gin.Context)
}

func registerUserManagementRoutes(users *gin.RouterGroup, userHandler userRouteHandler, access userRouteAccess) {
	users.GET("", access.List, userHandler.ListUsers)
	users.POST("", access.Create, userHandler.CreateUser)
	users.GET("/:id", access.Read, userHandler.GetUser)
	users.GET("/:id/login-methods", access.LoginMethods, userHandler.ListUserLoginMethods)
	users.PATCH("/:id", access.Update, userHandler.UpdateUser)
	users.PATCH("/:id/login-methods/:provider/primary", access.UpdatePrimaryLoginMethod, userHandler.PatchUserPrimaryLoginMethod)
	users.DELETE("/:id", access.Delete, userHandler.DeleteUser)
	users.PATCH("/:id/status", access.UpdateStatus, userHandler.UpdateUserStatus)
	users.POST("/:id/reset-password", access.ResetPassword, userHandler.ResetUserPassword)
	users.GET("/:id/audit-logs", access.AuditLogs, userHandler.GetAuditLogs)
	users.GET("/:id/roles", access.Roles, userHandler.GetUserRoles)
	users.GET("/:id/permissions", access.Permissions, userHandler.GetUserPermissions)
	users.GET("/:id/sessions", access.Sessions, userHandler.GetUserSessions)
	users.DELETE("/:id/sessions/:sessionId", access.RevokeSession, userHandler.RevokeUserSession)
	users.GET("/:id/security-summary", access.SecuritySummary, userHandler.GetSecuritySummary)
	users.GET("/:id/login-logs", access.LoginLogs, userHandler.GetLoginLogs)
}

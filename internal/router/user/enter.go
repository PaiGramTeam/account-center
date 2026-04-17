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
	userHandler := &handler.ApiGroupApp.UserApiGroup.Handler
	registerUserManagementRoutes(rg.Group("/users"), userHandler, userRouteAccess{
		List:            middleware.CasbinMiddleware(),
		Create:          middleware.CasbinMiddleware(),
		Read:            middleware.SelfOrCasbinPermission(),
		Update:          middleware.SelfOrCasbinPermission(),
		Delete:          middleware.CasbinMiddleware(),
		UpdateStatus:    middleware.CasbinMiddleware(),
		ResetPassword:   middleware.CasbinMiddleware(),
		AuditLogs:       middleware.SelfOrCasbinPermission(),
		Roles:           middleware.SelfOrCasbinPermission(),
		Permissions:     middleware.SelfOrCasbinPermission(),
		Sessions:        middleware.SelfOrCasbinPermission(),
		RevokeSession:   middleware.SelfOrCasbinPermission(),
		SecuritySummary: middleware.SelfOrCasbinPermission(),
		LoginLogs:       middleware.SelfOrCasbinPermission(),
	})

	_ = db
}

type userRouteAccess struct {
	List            gin.HandlerFunc
	Create          gin.HandlerFunc
	Read            gin.HandlerFunc
	Update          gin.HandlerFunc
	Delete          gin.HandlerFunc
	UpdateStatus    gin.HandlerFunc
	ResetPassword   gin.HandlerFunc
	AuditLogs       gin.HandlerFunc
	Roles           gin.HandlerFunc
	Permissions     gin.HandlerFunc
	Sessions        gin.HandlerFunc
	RevokeSession   gin.HandlerFunc
	SecuritySummary gin.HandlerFunc
	LoginLogs       gin.HandlerFunc
}

type userRouteHandler interface {
	ListUsers(*gin.Context)
	CreateUser(*gin.Context)
	GetUser(*gin.Context)
	UpdateUser(*gin.Context)
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
	users.PATCH("/:id", access.Update, userHandler.UpdateUser)
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

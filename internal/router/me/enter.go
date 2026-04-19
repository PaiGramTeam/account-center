package me

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/handler"
	"paigram/internal/middleware"
)

// RouterGroup holds phase-two current-user routers.
type RouterGroup struct {
	AuthConfig config.AuthConfig
}

// Init registers the phase-two /me routes.
func (r *RouterGroup) Init(rg *gin.RouterGroup, _ *gorm.DB) {
	fresh := middleware.RequireFreshSession(r.AuthConfig)
	me := rg.Group("/me")
	{
		me.GET("", handler.ApiGroupApp.MeApiGroup.CurrentUserHandler.GetMe)
		me.GET("/dashboard-summary", handler.ApiGroupApp.MeApiGroup.CurrentUserHandler.GetDashboardSummary)
		me.GET("/emails", handler.ApiGroupApp.MeApiGroup.CurrentUserHandler.ListEmails)
		me.POST("/emails", handler.ApiGroupApp.MeApiGroup.CurrentUserHandler.CreateEmail)
		me.DELETE("/emails/:emailId", handler.ApiGroupApp.MeApiGroup.CurrentUserHandler.DeleteEmail)
		me.PATCH("/emails/:emailId/primary", handler.ApiGroupApp.MeApiGroup.CurrentUserHandler.PatchPrimaryEmail)
		me.POST("/emails/:emailId/verify", handler.ApiGroupApp.MeApiGroup.CurrentUserHandler.VerifyEmail)
		me.GET("/login-methods", handler.ApiGroupApp.MeApiGroup.CurrentUserHandler.ListLoginMethods)
		me.PUT("/login-methods/:provider", fresh, handler.ApiGroupApp.AuthApiGroup.Handler.StartBindLoginMethod)
		me.DELETE("/login-methods/:provider", handler.ApiGroupApp.MeApiGroup.CurrentUserHandler.DeleteLoginMethod)
		me.GET("/security/overview", handler.ApiGroupApp.MeApiGroup.SecurityHandler.GetOverview)
		me.PUT("/security/password", fresh, handler.ApiGroupApp.MeApiGroup.SecurityHandler.UpdatePassword)
		me.POST("/security/2fa/setup", fresh, handler.ApiGroupApp.MeApiGroup.SecurityHandler.SetupTwoFactor)
		me.POST("/security/2fa/confirm", fresh, handler.ApiGroupApp.MeApiGroup.SecurityHandler.ConfirmTwoFactor)
		me.DELETE("/security/2fa", fresh, handler.ApiGroupApp.MeApiGroup.SecurityHandler.DisableTwoFactor)
		me.POST("/security/2fa/backup-codes/regenerate", fresh, handler.ApiGroupApp.MeApiGroup.SecurityHandler.RegenerateBackupCodes)
		me.GET("/sessions", handler.ApiGroupApp.MeApiGroup.SessionHandler.ListSessions)
		me.DELETE("/sessions/:sessionId", handler.ApiGroupApp.MeApiGroup.SessionHandler.RevokeSession)
		me.GET("/activity-logs", handler.ApiGroupApp.MeApiGroup.ActivityHandler.ListLogs)
	}
}

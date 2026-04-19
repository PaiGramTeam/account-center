package platformbinding

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/handler"
	"paigram/internal/middleware"
)

// RouterGroup holds platform binding routers.
type RouterGroup struct{}

// Init registers platform binding routes on the provided router group.
func (r *RouterGroup) Init(rg *gin.RouterGroup, _ *gorm.DB) {
	meHandler := &handler.ApiGroupApp.PlatformBindingApiGroup.MeHandler
	adminHandler := &handler.ApiGroupApp.PlatformBindingApiGroup.AdminHandler

	me := rg.Group("/me")
	{
		me.GET("/platform-accounts", meHandler.ListBindings)
		me.POST("/platform-accounts", meHandler.CreateBinding)
		me.GET("/platform-accounts/:bindingId", meHandler.GetBinding)
		me.PATCH("/platform-accounts/:bindingId", meHandler.PatchBinding)
		me.POST("/platform-accounts/:bindingId/refresh", meHandler.RefreshBinding)
		me.PUT("/platform-accounts/:bindingId/credential", meHandler.PutCredential)
		me.GET("/platform-accounts/:bindingId/runtime-summary", meHandler.GetRuntimeSummary)
		me.PATCH("/platform-accounts/:bindingId/primary-profile", meHandler.PatchPrimaryProfile)
		me.DELETE("/platform-accounts/:bindingId", meHandler.DeleteBinding)
		me.GET("/platform-accounts/:bindingId/profiles", meHandler.ListProfiles)
		me.GET("/platform-accounts/:bindingId/consumer-grants", meHandler.ListConsumerGrants)
		me.PUT("/platform-accounts/:bindingId/consumer-grants/:consumer", meHandler.PutConsumerGrant)
	}

	admin := rg.Group("/admin/platform-accounts")
	admin.Use(middleware.CasbinMiddleware())
	{
		admin.GET("", adminHandler.ListBindings)
		admin.GET("/:bindingId", adminHandler.GetBinding)
		admin.GET("/:bindingId/profiles", adminHandler.ListProfiles)
		admin.PUT("/:bindingId/credential", adminHandler.PutCredential)
		admin.GET("/:bindingId/runtime-summary", adminHandler.GetRuntimeSummary)
		admin.GET("/:bindingId/consumer-grants", adminHandler.ListConsumerGrants)
		admin.PUT("/:bindingId/consumer-grants/:consumer", adminHandler.PutConsumerGrant)
		admin.POST("/:bindingId/refresh", adminHandler.RefreshBinding)
		admin.DELETE("/:bindingId", adminHandler.DeleteBinding)
	}
}

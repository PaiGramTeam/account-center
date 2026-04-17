package platform

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/handler"
	"paigram/internal/middleware"
)

// RouterGroup holds platform-related routers.
type RouterGroup struct{}

// Init registers platform routes on the provided router group.
func (r *RouterGroup) Init(rg *gin.RouterGroup, _ *gorm.DB) {
	platformHandler := &handler.ApiGroupApp.PlatformApiGroup.Handler
	platformAdminHandler := &handler.ApiGroupApp.PlatformApiGroup.AdminHandler

	me := rg.Group("/me")
	{
		me.GET("/platforms", platformHandler.ListPlatforms)
		me.GET("/platforms/:platform/schema", platformHandler.GetPlatformSchema)
		me.GET("/platform-accounts/:refId/summary", platformHandler.GetPlatformAccountSummary)
	}

	platformServices := rg.Group("/platform-services")
	platformServices.Use(middleware.CasbinMiddleware())
	{
		platformServices.GET("", platformAdminHandler.ListPlatformServices)
		platformServices.GET("/:id", platformAdminHandler.GetPlatformService)
		platformServices.POST("", platformAdminHandler.CreatePlatformService)
		platformServices.PATCH("/:id", platformAdminHandler.UpdatePlatformService)
		platformServices.DELETE("/:id", platformAdminHandler.DeletePlatformService)
		platformServices.POST("/:id/check", platformAdminHandler.CheckPlatformService)
	}
}

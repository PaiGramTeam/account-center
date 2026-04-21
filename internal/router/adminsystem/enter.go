package adminsystem

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/handler"
	"paigram/internal/middleware"
)

// RouterGroup holds phase-two admin system routers.
type RouterGroup struct{}

// Init registers the phase-two /admin/system routes.
func (r *RouterGroup) Init(rg *gin.RouterGroup, _ *gorm.DB) {
	adminGate := middleware.RequireRoleMiddleware("admin")
	permissionCheck := middleware.CasbinMiddleware()
	adminSystem := rg.Group("/admin/system")
	adminSystem.Use(adminGate, permissionCheck)
	{
		settings := adminSystem.Group("/settings")
		{
			settings.GET("/site", handler.ApiGroupApp.AdminSystemApiGroup.SettingsHandler.GetSite)
			settings.PATCH("/site", handler.ApiGroupApp.AdminSystemApiGroup.SettingsHandler.PatchSite)
			settings.GET("/registration", handler.ApiGroupApp.AdminSystemApiGroup.SettingsHandler.GetRegistration)
			settings.PATCH("/registration", handler.ApiGroupApp.AdminSystemApiGroup.SettingsHandler.PatchRegistration)
			settings.GET("/email", handler.ApiGroupApp.AdminSystemApiGroup.SettingsHandler.GetEmail)
			settings.PATCH("/email", handler.ApiGroupApp.AdminSystemApiGroup.SettingsHandler.PatchEmail)
			settings.GET("/legal", handler.ApiGroupApp.AdminSystemApiGroup.LegalHandler.GetPublishedDocuments)
			settings.PATCH("/legal", handler.ApiGroupApp.AdminSystemApiGroup.LegalHandler.UpsertDocuments)
		}

		adminSystem.GET("/auth-controls", handler.ApiGroupApp.AdminSystemApiGroup.SettingsHandler.GetAuthControls)
		adminSystem.PATCH("/auth-controls", handler.ApiGroupApp.AdminSystemApiGroup.SettingsHandler.PatchAuthControls)

		platformServices := adminSystem.Group("/platform-services")
		{
			platformServices.GET("", handler.ApiGroupApp.AdminSystemApiGroup.PlatformServiceHandler.ListPlatformServices)
			platformServices.GET("/:id", handler.ApiGroupApp.AdminSystemApiGroup.PlatformServiceHandler.GetPlatformService)
			platformServices.POST("", handler.ApiGroupApp.AdminSystemApiGroup.PlatformServiceHandler.CreatePlatformService)
			platformServices.PATCH("/:id", handler.ApiGroupApp.AdminSystemApiGroup.PlatformServiceHandler.UpdatePlatformService)
			platformServices.DELETE("/:id", handler.ApiGroupApp.AdminSystemApiGroup.PlatformServiceHandler.DeletePlatformService)
			platformServices.POST("/:id/check", handler.ApiGroupApp.AdminSystemApiGroup.PlatformServiceHandler.CheckPlatformService)
		}
	}
}

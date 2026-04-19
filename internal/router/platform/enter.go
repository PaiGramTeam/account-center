package platform

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/handler"
)

// RouterGroup holds platform-related routers.
type RouterGroup struct{}

// Init registers platform routes on the provided router group.
func (r *RouterGroup) Init(rg *gin.RouterGroup, _ *gorm.DB) {
	platformHandler := &handler.ApiGroupApp.PlatformApiGroup.Handler

	me := rg.Group("/me")
	{
		me.GET("/platforms", platformHandler.ListPlatforms)
		me.GET("/platforms/:platform/schema", platformHandler.GetPlatformSchema)
		me.GET("/platform-accounts/:bindingId/summary", platformHandler.GetPlatformAccountSummary)
	}
}

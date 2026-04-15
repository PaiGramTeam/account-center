package casbin

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/handler"
	"paigram/internal/middleware"
)

// RouterGroup holds casbin-related routers.
type RouterGroup struct{}

// Init registers casbin routes on the provided router group.
func (r *RouterGroup) Init(rg *gin.RouterGroup, db *gorm.DB) {
	_ = db

	handlers := &handler.ApiGroupApp.CasbinApiGroup.CasbinHandler

	casbinGroup := rg.Group("/casbin")
	authorityPolicies := casbinGroup.Group("/authorities")
	authorityPolicies.Use(middleware.CasbinMiddleware())
	authorityPolicies.Use(middleware.AdminOnlyMiddleware())
	{
		authorityPolicies.GET("/:id/policies", handlers.GetAuthorityPolicies)
		authorityPolicies.PUT("/:id/policies", handlers.ReplaceAuthorityPolicies)
	}
}

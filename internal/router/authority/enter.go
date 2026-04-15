package authority

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/handler"
	"paigram/internal/middleware"
)

// RouterGroup holds authority-related routers.
type RouterGroup struct{}

// Init registers authority routes on the provided router group.
func (r *RouterGroup) Init(rg *gin.RouterGroup, db *gorm.DB) {
	// Get authority handlers from global API group
	handlers := &handler.ApiGroupApp.AuthorityApiGroup

	// Authority routes (继承 rg 的认证和限流中间件)
	authGroup := rg.Group("/authorities")
	authGroup.Use(middleware.CasbinMiddleware())
	{
		// 角色管理
		authGroup.POST("", handlers.AuthorityHandler.CreateAuthority)
		authGroup.GET("", handlers.AuthorityHandler.ListAuthorities)
		authGroup.GET("/:id", handlers.AuthorityHandler.GetAuthority)
		authGroup.PUT("/:id", handlers.AuthorityHandler.UpdateAuthority)
		authGroup.DELETE("/:id", handlers.AuthorityHandler.DeleteAuthority)
		authGroup.GET("/:id/users", handlers.AuthorityHandler.GetAuthorityUsers)
		authGroup.PUT("/:id/users", middleware.AdminOnlyMiddleware(), handlers.AuthorityHandler.ReplaceAuthorityUsers)

		// 权限分配
		authGroup.POST("/:id/permissions", middleware.AdminOnlyMiddleware(), handlers.AuthorityHandler.AssignPermissions)
		authGroup.GET("/:id/permissions", handlers.AuthorityHandler.GetRolePermissions)
	}
}

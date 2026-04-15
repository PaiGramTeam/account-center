package router

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	routerAuthority "paigram/internal/router/authority"
	routerCasbin "paigram/internal/router/casbin"
	routerPlatform "paigram/internal/router/platform"
	routerUser "paigram/internal/router/user"
)

// RouterGroup aggregates all router groups.
type RouterGroup struct {
	UserRouterGroup      routerUser.RouterGroup
	CasbinRouterGroup    routerCasbin.RouterGroup
	AuthorityRouterGroup routerAuthority.RouterGroup
	PlatformRouterGroup  routerPlatform.RouterGroup
}

// RouterGroupApp is the global router instance.
var RouterGroupApp = new(RouterGroup)

// InitializeRouterGroups sets up all router groups with dependencies.
func InitializeRouterGroups(rg *gin.RouterGroup, db *gorm.DB) {
	// Initialize user router group
	RouterGroupApp.UserRouterGroup.Init(rg, db)

	// Initialize authority router group
	RouterGroupApp.AuthorityRouterGroup.Init(rg, db)

	// Initialize casbin router group
	RouterGroupApp.CasbinRouterGroup.Init(rg, db)

	// Initialize platform router group
	RouterGroupApp.PlatformRouterGroup.Init(rg, db)
}

package router

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/config"
	routerAdmin "paigram/internal/router/admin"
	routerAdminAudit "paigram/internal/router/adminaudit"
	routerAdminSystem "paigram/internal/router/adminsystem"
	routerAuthority "paigram/internal/router/authority"
	routerCasbin "paigram/internal/router/casbin"
	routerMe "paigram/internal/router/me"
	routerPlatform "paigram/internal/router/platform"
	routerPlatformBinding "paigram/internal/router/platformbinding"
	routerUser "paigram/internal/router/user"
)

// RouterGroup aggregates all router groups.
type RouterGroup struct {
	AdminRouterGroup           routerAdmin.RouterGroup
	UserRouterGroup            routerUser.RouterGroup
	CasbinRouterGroup          routerCasbin.RouterGroup
	AuthorityRouterGroup       routerAuthority.RouterGroup
	MeRouterGroup              routerMe.RouterGroup
	AdminSystemRouterGroup     routerAdminSystem.RouterGroup
	AdminAuditRouterGroup      routerAdminAudit.RouterGroup
	PlatformRouterGroup        routerPlatform.RouterGroup
	PlatformBindingRouterGroup routerPlatformBinding.RouterGroup
}

// RouterGroupApp is the global router instance.
var RouterGroupApp = new(RouterGroup)

// InitializeRouterGroups sets up all router groups with dependencies.
func InitializeRouterGroups(rg *gin.RouterGroup, db *gorm.DB, authCfg config.AuthConfig) {
	RouterGroupApp.MeRouterGroup.AuthConfig = authCfg

	// Initialize admin router group
	RouterGroupApp.AdminRouterGroup.Init(rg, db)

	// Initialize phase-two router groups
	RouterGroupApp.MeRouterGroup.Init(rg, db)
	RouterGroupApp.AdminSystemRouterGroup.Init(rg, db)
	RouterGroupApp.AdminAuditRouterGroup.Init(rg, db)

	// Initialize platform router group
	RouterGroupApp.PlatformRouterGroup.Init(rg, db)

	// Initialize platform binding router group
	RouterGroupApp.PlatformBindingRouterGroup.Init(rg, db)
}

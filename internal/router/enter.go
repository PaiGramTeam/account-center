package router

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/permission"
	routerUser "paigram/internal/router/user"
)

// RouterGroup aggregates all router groups.
type RouterGroup struct {
	UserRouterGroup routerUser.RouterGroup
}

// RouterGroupApp is the global router instance.
var RouterGroupApp = new(RouterGroup)

// InitializeRouterGroups sets up all router groups with dependencies.
func InitializeRouterGroups(rg *gin.RouterGroup, db *gorm.DB, permMgr *permission.Manager) {
	// Initialize user router group
	RouterGroupApp.UserRouterGroup.Init(rg, db, permMgr)
}

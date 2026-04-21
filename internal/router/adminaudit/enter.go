package adminaudit

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/handler"
	"paigram/internal/middleware"
)

// RouterGroup holds phase-two admin audit routers.
type RouterGroup struct{}

// Init registers the phase-two /admin/audit-logs routes.
func (r *RouterGroup) Init(rg *gin.RouterGroup, _ *gorm.DB) {
	adminAudit := rg.Group("/admin")
	adminAudit.Use(middleware.RequireRoleMiddleware("admin"), middleware.CasbinMiddleware())
	{
		adminAudit.GET("/audit-logs", handler.ApiGroupApp.AdminAuditApiGroup.AuditHandler.ListAuditLogs)
		adminAudit.GET("/audit-logs/:id", handler.ApiGroupApp.AdminAuditApiGroup.AuditHandler.GetAuditLog)
	}
}

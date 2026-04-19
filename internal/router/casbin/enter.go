package casbin

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// RouterGroup holds casbin-related routers.
type RouterGroup struct{}

// Init no longer registers public casbin management routes.
func (r *RouterGroup) Init(_ *gin.RouterGroup, _ *gorm.DB) {
}

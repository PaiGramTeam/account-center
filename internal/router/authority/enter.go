package authority

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// RouterGroup holds authority-related routers.
type RouterGroup struct{}

// Init no longer registers public authority management routes.
func (r *RouterGroup) Init(_ *gin.RouterGroup, _ *gorm.DB) {
}

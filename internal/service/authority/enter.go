package authority

import (
	"gorm.io/gorm"
	servicecasbin "paigram/internal/service/casbin"
)

// ServiceGroup holds authority-related services.
type ServiceGroup struct {
	AuthorityService
}

// NewServiceGroup creates an authority service group with dependencies.
func NewServiceGroup(db *gorm.DB, casbinService *servicecasbin.CasbinService) *ServiceGroup {
	return &ServiceGroup{
		AuthorityService: AuthorityService{db: db, casbinService: casbinService},
	}
}

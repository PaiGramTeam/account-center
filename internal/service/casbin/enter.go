package casbin

import "gorm.io/gorm"

// ServiceGroup holds casbin-related services.
type ServiceGroup struct {
	CasbinService
}

// NewServiceGroup creates a casbin service group with dependencies.
func NewServiceGroup(db *gorm.DB) *ServiceGroup {
	return &ServiceGroup{
		CasbinService: CasbinService{db: db},
	}
}

package platform

import (
	"gorm.io/gorm"
)

// ServiceGroup aggregates platform-related services.
type ServiceGroup struct {
	PlatformService PlatformService
}

// NewServiceGroup creates the platform service group.
func NewServiceGroup(db *gorm.DB) *ServiceGroup {
	return &ServiceGroup{PlatformService: PlatformService{db: db}}
}

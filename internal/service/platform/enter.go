package platform

import (
	"time"

	"gorm.io/gorm"
)

// ServiceGroup aggregates platform-related services.
type ServiceGroup struct {
	PlatformService PlatformService
}

// NewServiceGroup creates the platform service group.
func NewServiceGroup(db *gorm.DB) *ServiceGroup {
	service := PlatformService{db: db}
	service.SetHealthChecker(newGRPCHealthChecker(2 * time.Second))

	return &ServiceGroup{PlatformService: service}
}

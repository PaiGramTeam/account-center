package audit

import "gorm.io/gorm"

// ServiceGroup holds unified audit services.
type ServiceGroup struct {
	AuditService AuditService
}

// NewServiceGroup creates the unified audit service group.
func NewServiceGroup(db *gorm.DB) *ServiceGroup {
	return &ServiceGroup{AuditService: *NewAuditService(db)}
}

package adminaudit

import "gorm.io/gorm"

// ServiceGroup holds phase-two admin audit services.
type ServiceGroup struct {
	AuditService AuditService
}

// NewServiceGroup creates the phase-two admin audit service group.
func NewServiceGroup(_ *gorm.DB) *ServiceGroup {
	return &ServiceGroup{AuditService: *NewAuditService()}
}

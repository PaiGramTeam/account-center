package adminsystem

import "gorm.io/gorm"

// ServiceGroup holds phase-two admin system services.
type ServiceGroup struct {
	SettingsService SettingsService
}

// NewServiceGroup creates the phase-two admin system service group.
func NewServiceGroup(_ *gorm.DB) *ServiceGroup {
	return &ServiceGroup{SettingsService: *NewSettingsService()}
}

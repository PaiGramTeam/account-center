package systemconfig

import (
	"errors"

	"gorm.io/gorm"
)

var ErrInvalidSettingsDomain = errors.New("invalid settings domain")

// ServiceGroup holds admin system settings and legal services.
type ServiceGroup struct {
	SettingsService SettingsService
	LegalService    LegalService
}

// NewServiceGroup creates the admin system config service group.
func NewServiceGroup(db *gorm.DB) *ServiceGroup {
	return &ServiceGroup{
		SettingsService: *NewSettingsService(db),
		LegalService:    *NewLegalService(db),
	}
}

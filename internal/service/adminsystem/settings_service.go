package adminsystem

import "context"

// SettingsService serves admin system settings.
type SettingsService struct{}

// NewSettingsService creates a settings service.
func NewSettingsService() *SettingsService {
	return &SettingsService{}
}

// GetSiteSettings returns a phase-two stub payload.
func (s *SettingsService) GetSiteSettings(context.Context) map[string]any {
	return map[string]any{
		"scope": "site",
	}
}

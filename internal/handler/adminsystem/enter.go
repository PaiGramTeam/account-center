package adminsystem

import (
	serviceplatform "paigram/internal/service/platform"
	servicesystemconfig "paigram/internal/service/systemconfig"
)

// ApiGroup holds phase-two admin system handlers.
type ApiGroup struct {
	SettingsHandler        SettingsHandler
	LegalHandler           LegalHandler
	PlatformServiceHandler PlatformServiceHandler
}

// NewApiGroup creates the phase-two admin system handler group.
func NewApiGroup(serviceGroup *servicesystemconfig.ServiceGroup, platformGroup *serviceplatform.ServiceGroup) *ApiGroup {
	return &ApiGroup{
		SettingsHandler:        *NewSettingsHandler(&serviceGroup.SettingsService),
		LegalHandler:           *NewLegalHandler(&serviceGroup.LegalService),
		PlatformServiceHandler: *NewPlatformServiceHandler(&platformGroup.PlatformService),
	}
}

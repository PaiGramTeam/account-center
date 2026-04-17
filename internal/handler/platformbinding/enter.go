package platformbinding

import serviceplatformbinding "paigram/internal/service/platformbinding"

// ApiGroup holds platform binding API handlers.
type ApiGroup struct {
	MeHandler    MeHandler
	AdminHandler AdminHandler
}

// NewApiGroup creates a platform binding API group with service dependencies.
func NewApiGroup(serviceGroup *serviceplatformbinding.ServiceGroup) *ApiGroup {
	return &ApiGroup{
		MeHandler: *NewMeHandler(
			&serviceGroup.BindingService,
			&serviceGroup.ProfileProjectionService,
			&serviceGroup.GrantService,
		),
		AdminHandler: *NewAdminHandler(
			&serviceGroup.BindingService,
			&serviceGroup.ProfileProjectionService,
			&serviceGroup.GrantService,
		),
	}
}

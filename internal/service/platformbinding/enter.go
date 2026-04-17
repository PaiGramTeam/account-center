package platformbinding

import "gorm.io/gorm"

type ServiceGroup struct {
	BindingService           BindingService
	GrantService             GrantService
	ProfileProjectionService ProfileProjectionService
}

func NewServiceGroup(db *gorm.DB) *ServiceGroup {
	return &ServiceGroup{
		BindingService:           *NewBindingService(db),
		GrantService:             *NewGrantService(db),
		ProfileProjectionService: *NewProfileProjectionService(db),
	}
}

package platformbinding

import (
	serviceplatform "paigram/internal/service/platform"

	"gorm.io/gorm"
)

type ServiceGroup struct {
	BindingService           BindingService
	GrantService             GrantService
	ProfileProjectionService ProfileProjectionService
	OrchestrationService     OrchestrationService
	RuntimeSummaryService    RuntimeSummaryService
}

func NewServiceGroup(db *gorm.DB, platformService *serviceplatform.PlatformService) *ServiceGroup {
	bindingService := NewBindingService(db)
	profileProjectionService := NewProfileProjectionService(db)
	return &ServiceGroup{
		BindingService:           *bindingService,
		GrantService:             *NewGrantService(db),
		ProfileProjectionService: *profileProjectionService,
		OrchestrationService:     *NewOrchestrationService(bindingService, platformService, serviceplatform.NewGRPCGenericCredentialGateway(nil), profileProjectionService),
		RuntimeSummaryService:    *NewRuntimeSummaryService(platformService, bindingService),
	}
}

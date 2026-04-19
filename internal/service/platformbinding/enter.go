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
	return &ServiceGroup{
		BindingService:           *bindingService,
		GrantService:             *NewGrantService(db),
		ProfileProjectionService: *NewProfileProjectionService(db),
		OrchestrationService:     *NewOrchestrationService(bindingService, platformService, serviceplatform.NewGRPCGenericCredentialGateway(nil)),
		RuntimeSummaryService:    *NewRuntimeSummaryService(platformService, bindingService),
	}
}

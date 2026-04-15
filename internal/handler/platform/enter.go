package platform

import serviceplatform "paigram/internal/service/platform"

// ApiGroup holds platform-related API handlers.
type ApiGroup struct {
	Handler Handler
}

// NewApiGroup creates a platform API group with service dependencies.
func NewApiGroup(serviceGroup *serviceplatform.ServiceGroup) *ApiGroup {
	return &ApiGroup{Handler: *NewHandler(&serviceGroup.PlatformService)}
}

package casbin

import servicecasbin "paigram/internal/service/casbin"

// ApiGroup holds casbin-related API handlers.
type ApiGroup struct {
	CasbinHandler
}

// NewApiGroup creates a casbin API group with service dependencies.
func NewApiGroup(serviceGroup *servicecasbin.ServiceGroup) *ApiGroup {
	return &ApiGroup{
		CasbinHandler: *NewCasbinHandler(&serviceGroup.CasbinService),
	}
}

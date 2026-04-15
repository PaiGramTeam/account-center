package authority

import "paigram/internal/service/authority"

type ApiGroup struct {
	AuthorityHandler
}

func NewApiGroup(serviceGroup *authority.ServiceGroup) *ApiGroup {
	return &ApiGroup{
		AuthorityHandler: *NewAuthorityHandler(&serviceGroup.AuthorityService),
	}
}

package adminaudit

import serviceaudit "paigram/internal/service/audit"

// ApiGroup holds phase-two admin audit handlers.
type ApiGroup struct {
	AuditHandler AuditHandler
}

// NewApiGroup creates the phase-two admin audit handler group.
func NewApiGroup(serviceGroup *serviceaudit.ServiceGroup) *ApiGroup {
	return &ApiGroup{
		AuditHandler: *NewAuditHandler(&serviceGroup.AuditService),
	}
}

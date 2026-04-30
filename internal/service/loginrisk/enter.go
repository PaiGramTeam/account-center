package loginrisk

import "gorm.io/gorm"

// ServiceGroup aggregates login-risk services.
type ServiceGroup struct {
	Analyzer Analyzer
}

// NewServiceGroup creates the login-risk service group.
func NewServiceGroup(db *gorm.DB) *ServiceGroup {
	return &ServiceGroup{Analyzer: *NewAnalyzer(db)}
}

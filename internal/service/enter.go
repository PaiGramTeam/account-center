package service

import (
	"paigram/internal/service/authority"
	"paigram/internal/service/casbin"
	"paigram/internal/service/user"

	"gorm.io/gorm"
)

// ServiceGroup aggregates all service groups.
type ServiceGroup struct {
	UserServiceGroup      user.ServiceGroup
	CasbinServiceGroup    casbin.ServiceGroup
	AuthorityServiceGroup authority.ServiceGroup
}

// NewServiceGroup creates the global service group with all dependencies.
func NewServiceGroup(db *gorm.DB) *ServiceGroup {
	casbinGroup := casbin.NewServiceGroup(db)
	return &ServiceGroup{
		UserServiceGroup:      *user.NewServiceGroup(db),
		CasbinServiceGroup:    *casbinGroup,
		AuthorityServiceGroup: *authority.NewServiceGroup(db, &casbinGroup.CasbinService),
	}
}

// ServiceGroupApp is the global service instance.
var ServiceGroupApp = new(ServiceGroup)

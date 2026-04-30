package service

import (
	serviceAudit "paigram/internal/service/audit"
	"paigram/internal/service/authority"
	"paigram/internal/service/casbin"
	"paigram/internal/service/geolocation"
	"paigram/internal/service/loginrisk"
	serviceMe "paigram/internal/service/me"
	"paigram/internal/service/platform"
	"paigram/internal/service/platformbinding"
	serviceSystemConfig "paigram/internal/service/systemconfig"
	"paigram/internal/service/user"

	"gorm.io/gorm"
)

// ServiceGroup aggregates all service groups.
type ServiceGroup struct {
	UserServiceGroup        user.ServiceGroup
	CasbinServiceGroup      casbin.ServiceGroup
	AuthorityServiceGroup   authority.ServiceGroup
	MeServiceGroup          serviceMe.ServiceGroup
	SystemConfigGroup       serviceSystemConfig.ServiceGroup
	AuditGroup              serviceAudit.ServiceGroup
	PlatformServiceGroup    platform.ServiceGroup
	PlatformBindingGroup    platformbinding.ServiceGroup
	LoginRiskServiceGroup   loginrisk.ServiceGroup
	GeolocationServiceGroup geolocation.ServiceGroup
}

// NewServiceGroup creates the global service group with all dependencies.
func NewServiceGroup(db *gorm.DB) *ServiceGroup {
	casbinGroup := casbin.NewServiceGroup(db)
	platformGroup := platform.NewServiceGroup(db)
	return &ServiceGroup{
		UserServiceGroup:        *user.NewServiceGroup(db),
		CasbinServiceGroup:      *casbinGroup,
		AuthorityServiceGroup:   *authority.NewServiceGroup(db, &casbinGroup.CasbinService),
		MeServiceGroup:          *serviceMe.NewServiceGroup(db, nil),
		SystemConfigGroup:       *serviceSystemConfig.NewServiceGroup(db),
		AuditGroup:              *serviceAudit.NewServiceGroup(db),
		PlatformServiceGroup:    *platformGroup,
		PlatformBindingGroup:    *platformbinding.NewServiceGroup(db, &platformGroup.PlatformService),
		LoginRiskServiceGroup:   *loginrisk.NewServiceGroup(db),
		GeolocationServiceGroup: *geolocation.NewServiceGroup(),
	}
}

// ServiceGroupApp is the global service instance.
var ServiceGroupApp = new(ServiceGroup)

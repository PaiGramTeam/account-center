package handler

import (
	"errors"

	"gorm.io/gorm"

	"paigram/internal/casbin"
	"paigram/internal/config"
	handlerAdminAudit "paigram/internal/handler/adminaudit"
	handlerAdminSystem "paigram/internal/handler/adminsystem"
	handlerAuthority "paigram/internal/handler/authority"
	handlerCasbin "paigram/internal/handler/casbin"
	handlerMe "paigram/internal/handler/me"
	handlerPlatform "paigram/internal/handler/platform"
	handlerPlatformBinding "paigram/internal/handler/platformbinding"
	handlerUser "paigram/internal/handler/user"
	"paigram/internal/service"
	serviceAudit "paigram/internal/service/audit"
	serviceAuthority "paigram/internal/service/authority"
	serviceCasbin "paigram/internal/service/casbin"
	serviceMe "paigram/internal/service/me"
	servicePlatform "paigram/internal/service/platform"
	servicePlatformBinding "paigram/internal/service/platformbinding"
	serviceSystemConfig "paigram/internal/service/systemconfig"
	serviceUser "paigram/internal/service/user"
	"paigram/internal/sessioncache"
)

// ApiGroup aggregates all API handler groups.
type ApiGroup struct {
	CasbinApiGroup          handlerCasbin.ApiGroup
	AuthorityApiGroup       handlerAuthority.ApiGroup
	PlatformApiGroup        handlerPlatform.ApiGroup
	PlatformBindingApiGroup handlerPlatformBinding.ApiGroup
	UserApiGroup            handlerUser.ApiGroup
	MeApiGroup              handlerMe.ApiGroup
	AdminSystemApiGroup     handlerAdminSystem.ApiGroup
	AdminAuditApiGroup      handlerAdminAudit.ApiGroup
}

// ApiGroupApp is the global API handler instance.
var ApiGroupApp = new(ApiGroup)

// InitializeApiGroups sets up all handler groups with dependencies.
func InitializeApiGroups(db *gorm.DB, cache sessioncache.Store, authCfg config.AuthConfig) error {
	if db == nil {
		return errors.New("initialize api groups: db is nil")
	}

	// Initialize Casbin enforcer
	if _, err := casbin.InitEnforcer(db); err != nil {
		return err
	}

	// Initialize service layer
	service.ServiceGroupApp.UserServiceGroup = *serviceUser.NewServiceGroup(db)
	service.ServiceGroupApp.CasbinServiceGroup = *serviceCasbin.NewServiceGroup(db)
	service.ServiceGroupApp.AuthorityServiceGroup = *serviceAuthority.NewServiceGroup(db, &service.ServiceGroupApp.CasbinServiceGroup.CasbinService)
	service.ServiceGroupApp.MeServiceGroup = *serviceMe.NewServiceGroup(db, cache)
	service.ServiceGroupApp.SystemConfigGroup = *serviceSystemConfig.NewServiceGroup(db)
	service.ServiceGroupApp.AuditGroup = *serviceAudit.NewServiceGroup(db)
	service.ServiceGroupApp.PlatformServiceGroup = *servicePlatform.NewServiceGroup(db)
	if err := service.ServiceGroupApp.PlatformServiceGroup.PlatformService.ConfigureAuth(authCfg); err != nil {
		return err
	}
	service.ServiceGroupApp.PlatformServiceGroup.PlatformService.SetGenericSummaryProxy(servicePlatform.NewGRPCGenericSummaryProxy(nil))
	service.ServiceGroupApp.PlatformBindingGroup = *servicePlatformBinding.NewServiceGroup(db, &service.ServiceGroupApp.PlatformServiceGroup.PlatformService)

	// Initialize API handlers (passing db temporarily for non-refactored methods)
	ApiGroupApp.CasbinApiGroup = *handlerCasbin.NewApiGroup(&service.ServiceGroupApp.CasbinServiceGroup)
	ApiGroupApp.AuthorityApiGroup = *handlerAuthority.NewApiGroup(&service.ServiceGroupApp.AuthorityServiceGroup)
	ApiGroupApp.PlatformApiGroup = *handlerPlatform.NewApiGroup(&service.ServiceGroupApp.PlatformServiceGroup)
	ApiGroupApp.PlatformBindingApiGroup = *handlerPlatformBinding.NewApiGroup(&service.ServiceGroupApp.PlatformBindingGroup)
	ApiGroupApp.UserApiGroup = *handlerUser.NewApiGroup(&service.ServiceGroupApp.UserServiceGroup, db, cache)
	ApiGroupApp.MeApiGroup = *handlerMe.NewApiGroup(&service.ServiceGroupApp.MeServiceGroup)
	ApiGroupApp.AdminSystemApiGroup = *handlerAdminSystem.NewApiGroup(&service.ServiceGroupApp.SystemConfigGroup, &service.ServiceGroupApp.PlatformServiceGroup)
	ApiGroupApp.AdminAuditApiGroup = *handlerAdminAudit.NewApiGroup(&service.ServiceGroupApp.AuditGroup)

	return nil
}

package handler

import (
	"errors"
	"gorm.io/gorm"

	"paigram/internal/casbin"
	handlerAuthority "paigram/internal/handler/authority"
	handlerCasbin "paigram/internal/handler/casbin"
	handlerUser "paigram/internal/handler/user"
	"paigram/internal/service"
	serviceAuthority "paigram/internal/service/authority"
	serviceCasbin "paigram/internal/service/casbin"
	serviceUser "paigram/internal/service/user"
	"paigram/internal/sessioncache"
)

// ApiGroup aggregates all API handler groups.
type ApiGroup struct {
	CasbinApiGroup    handlerCasbin.ApiGroup
	AuthorityApiGroup handlerAuthority.ApiGroup
	UserApiGroup      handlerUser.ApiGroup
}

// ApiGroupApp is the global API handler instance.
var ApiGroupApp = new(ApiGroup)

// InitializeApiGroups sets up all handler groups with dependencies.
func InitializeApiGroups(db *gorm.DB, cache sessioncache.Store) error {
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

	// Initialize API handlers (passing db temporarily for non-refactored methods)
	ApiGroupApp.CasbinApiGroup = *handlerCasbin.NewApiGroup(&service.ServiceGroupApp.CasbinServiceGroup)
	ApiGroupApp.AuthorityApiGroup = *handlerAuthority.NewApiGroup(&service.ServiceGroupApp.AuthorityServiceGroup)
	ApiGroupApp.UserApiGroup = *handlerUser.NewApiGroup(&service.ServiceGroupApp.UserServiceGroup, db, cache)

	return nil
}

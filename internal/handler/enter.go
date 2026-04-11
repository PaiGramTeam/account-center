package handler

import (
	"gorm.io/gorm"

	handlerUser "paigram/internal/handler/user"
	"paigram/internal/service"
	serviceUser "paigram/internal/service/user"
)

// ApiGroup aggregates all API handler groups.
type ApiGroup struct {
	UserApiGroup handlerUser.ApiGroup
}

// ApiGroupApp is the global API handler instance.
var ApiGroupApp = new(ApiGroup)

// InitializeApiGroups sets up all handler groups with dependencies.
func InitializeApiGroups(db *gorm.DB) {
	// Initialize service layer
	service.ServiceGroupApp.UserServiceGroup = *serviceUser.NewServiceGroup(db)

	// Initialize API handlers (passing db temporarily for non-refactored methods)
	ApiGroupApp.UserApiGroup = *handlerUser.NewApiGroup(&service.ServiceGroupApp.UserServiceGroup, db)
}

package user

import (
	"gorm.io/gorm"

	"paigram/internal/service/user"
	"paigram/internal/sessioncache"
)

// ApiGroup holds user-related API handlers.
type ApiGroup struct {
	Handler
}

// NewApiGroup creates a user API group with service dependencies.
func NewApiGroup(serviceGroup *user.ServiceGroup, db *gorm.DB, cache sessioncache.Store) *ApiGroup {
	return &ApiGroup{
		Handler: *NewHandlerWithDBAndCache(&serviceGroup.UserService, db, cache),
	}
}

package user

import (
	"gorm.io/gorm"

	"paigram/internal/service/user"
)

// ApiGroup holds user-related API handlers.
type ApiGroup struct {
	Handler
}

// NewApiGroup creates a user API group with service dependencies.
func NewApiGroup(serviceGroup *user.ServiceGroup, db *gorm.DB) *ApiGroup {
	return &ApiGroup{
		Handler: *NewHandlerWithDB(&serviceGroup.UserService, db),
	}
}

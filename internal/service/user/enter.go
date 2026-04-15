package user

import "gorm.io/gorm"

// ServiceGroup holds user-related services.
type ServiceGroup struct {
	UserService
	MiddlewareService
}

// NewServiceGroup creates a user service group with dependencies.
func NewServiceGroup(db *gorm.DB) *ServiceGroup {
	return &ServiceGroup{
		UserService:       UserService{db: db},
		MiddlewareService: MiddlewareService{db: db},
	}
}

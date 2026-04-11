package service

import (
	"paigram/internal/service/user"
)

// ServiceGroup aggregates all service groups.
type ServiceGroup struct {
	UserServiceGroup user.ServiceGroup
}

// ServiceGroupApp is the global service instance.
var ServiceGroupApp = new(ServiceGroup)

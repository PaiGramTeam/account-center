package me

import serviceme "paigram/internal/service/me"

// ApiGroup holds phase-two current-user handlers.
type ApiGroup struct {
	CurrentUserHandler CurrentUserHandler
	SecurityHandler    SecurityHandler
	SessionHandler     SessionHandler
	ActivityHandler    ActivityHandler
}

// NewApiGroup creates the phase-two current-user handler group.
func NewApiGroup(serviceGroup *serviceme.ServiceGroup) *ApiGroup {
	return &ApiGroup{
		CurrentUserHandler: *NewCurrentUserHandler(&serviceGroup.CurrentUserService),
		SecurityHandler:    *NewSecurityHandler(&serviceGroup.SecurityService),
		SessionHandler:     *NewSessionHandler(&serviceGroup.SessionService),
		ActivityHandler:    *NewActivityHandler(&serviceGroup.ActivityService),
	}
}

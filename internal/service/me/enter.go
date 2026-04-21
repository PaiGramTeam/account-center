package me

import (
	"errors"

	"gorm.io/gorm"

	"paigram/internal/sessioncache"
)

var (
	ErrEmailNotFound               = errors.New("email not found")
	ErrEmailNotVerified            = errors.New("email must be verified before setting as primary")
	ErrEmailAlreadyVerified        = errors.New("email already verified")
	ErrEmailRateLimited            = errors.New("verification email recently sent")
	ErrLastEmailCannotDelete       = errors.New("cannot delete the only email")
	ErrProviderNotBound            = errors.New("provider not bound to this account")
	ErrCannotRemoveLastLoginMethod = errors.New("cannot remove the last login method")
	ErrCannotUnbindPrimaryLogin    = errors.New("cannot unbind primary login method")
	ErrSessionNotFound             = errors.New("session not found")
	ErrInvalidSessionID            = errors.New("invalid session id")
	ErrNoPasswordLogin             = errors.New("user does not have password authentication")
	ErrInvalidPassword             = errors.New("incorrect password")
	ErrTwoFactorAlreadyEnabled     = errors.New("2FA is already enabled")
	ErrTwoFactorNotEnabled         = errors.New("2FA is not enabled")
	ErrTwoFactorSetupExpired       = errors.New("2FA setup expired or not found")
	ErrInvalidTwoFactorCode        = errors.New("invalid verification code")
	ErrEmailAlreadyAddedToAccount  = errors.New("email already added to this account")
	ErrEmailAlreadyInUse           = errors.New("email already in use by another account")
)

// ServiceGroup holds phase-two current-user services.
// CurrentUserService is also reused by admin login-method management handlers.
type ServiceGroup struct {
	CurrentUserService CurrentUserService
	SecurityService    SecurityService
	SessionService     SessionService
	ActivityService    ActivityService
}

// NewServiceGroup creates the phase-two current-user service group.
func NewServiceGroup(db *gorm.DB, cache sessioncache.Store) *ServiceGroup {
	if cache == nil {
		cache = sessioncache.NewNoopStore()
	}
	return &ServiceGroup{
		CurrentUserService: *NewCurrentUserService(db),
		SecurityService:    *NewSecurityService(db, cache),
		SessionService:     *NewSessionService(db, cache),
		ActivityService:    *NewActivityService(db),
	}
}

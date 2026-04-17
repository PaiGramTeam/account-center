package platformbinding

import "errors"

var (
	ErrBindingAlreadyOwned     = errors.New("platform binding is already owned by another user")
	ErrBindingNotFound         = errors.New("platform binding not found")
	ErrConsumerNotSupported    = errors.New("consumer is not supported")
	ErrGrantNotFound           = errors.New("consumer grant not found")
	ErrMultiplePrimaryProfiles = errors.New("multiple primary profiles are not supported")
	ErrPrimaryProfileNotOwned  = errors.New("primary profile must belong to binding")
)

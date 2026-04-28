package platformbinding

import "context"

type GrantInvalidationInput struct {
	BindingID           uint64
	OwnerUserID         uint64
	Platform            string
	PlatformServiceKey  string
	Consumer            string
	MinimumGrantVersion uint64
	ActorType           string
	ActorID             string
}

type GrantInvalidator interface {
	InvalidateConsumerGrant(ctx context.Context, input GrantInvalidationInput) error
}

package geolocation

// ServiceGroup aggregates geolocation services.
type ServiceGroup struct {
	Service Service
}

// NewServiceGroup creates the geolocation service group.
func NewServiceGroup() *ServiceGroup {
	return &ServiceGroup{Service: *NewService()}
}

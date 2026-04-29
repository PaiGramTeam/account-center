package user

import (
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/service/user"
	"paigram/internal/sessioncache"
)

// ApiGroup holds user-related API handlers.
type ApiGroup struct {
	Handler
}

// NewApiGroup creates a user API group with service dependencies. The
// security config flows through so admin-create / admin-reset paths hash
// at the operator-configured bcrypt cost (V8).
func NewApiGroup(serviceGroup *user.ServiceGroup, db *gorm.DB, cache sessioncache.Store, security config.SecurityConfig) *ApiGroup {
	return &ApiGroup{
		Handler: *NewHandlerWithDBCacheAndSecurity(&serviceGroup.UserService, db, cache, security),
	}
}

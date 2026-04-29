package auth

import (
	"paigram/internal/config"
	"paigram/internal/email"
	"paigram/internal/geolocation"
	"paigram/internal/sessioncache"

	"gorm.io/gorm"
)

// ApiGroup holds auth-related handlers.
type ApiGroup struct {
	Handler
}

// NewApiGroup creates an auth API group with shared dependencies.
func NewApiGroup(db *gorm.DB, cfg config.AuthConfig, frontendCfg config.FrontendConfig, emailService *email.Service, securityCfg config.SecurityConfig, cache sessioncache.Store, geoService *geolocation.Service) *ApiGroup {
	return &ApiGroup{
		Handler: *NewHandler(db, cfg, frontendCfg, emailService, securityCfg, cache, geoService),
	}
}

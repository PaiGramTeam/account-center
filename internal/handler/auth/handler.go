package auth

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/email"
	"paigram/internal/geolocation"
	"paigram/internal/security"
	"paigram/internal/sessioncache"
)

// Handler coordinates authentication-related endpoints (email + OAuth).
type Handler struct {
	db               *gorm.DB
	cfg              config.AuthConfig
	emailService     *email.Service
	securityCfg      config.SecurityConfig
	sessionCache     sessioncache.Store
	geoService       *geolocation.Service
	securityAnalyzer *security.Analyzer
	captchaVerifier  captchaVerifier
	// SECURITY: In-memory fallback for 2FA rate limiting when Redis is unavailable
	// WARNING: Not suitable for multi-instance deployments (no cross-instance sync)
	memory2FALimiter *memory2FARateLimiter
}

// NewHandler constructs an auth Handler.
func NewHandler(db *gorm.DB, cfg config.AuthConfig, emailService *email.Service, securityCfg config.SecurityConfig, cache sessioncache.Store, geoService *geolocation.Service) *Handler {
	if cache == nil {
		cache = sessioncache.NewNoopStore()
	}
	if geoService == nil {
		geoService = geolocation.NewService()
	}
	return &Handler{
		db:               db,
		cfg:              cfg,
		emailService:     emailService,
		securityCfg:      securityCfg,
		sessionCache:     cache,
		geoService:       geoService,
		securityAnalyzer: security.NewAnalyzer(db),
		captchaVerifier:  newCaptchaVerifier(cfg.Captcha.Turnstile),
		memory2FALimiter: newMemory2FARateLimiter(), // Always create in-memory fallback
	}
}

// RegisterRoutes binds authentication routes to the router group.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.POST("/register", h.RegisterEmail)
	rg.POST("/login", h.LoginWithEmail)
	rg.POST("/refresh", h.RefreshToken)
	rg.POST("/logout", h.Logout)
	rg.POST("/verify-email", h.VerifyEmail)
	rg.POST("/forgot-password", h.ForgotPassword)
	rg.POST("/reset-password", h.ResetPassword)

	oauth := rg.Group("/oauth")
	oauth.POST("/:provider/init", h.InitiateOAuth)
	oauth.POST("/:provider/callback", h.HandleOAuthCallback)
}

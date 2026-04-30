package auth

import (
	"context"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/email"
	"paigram/internal/middleware"
	"paigram/internal/service/geolocation"
	"paigram/internal/service/loginrisk"
	"paigram/internal/sessioncache"
)

// Handler coordinates authentication-related endpoints (email + OAuth).
type Handler struct {
	db               *gorm.DB
	cfg              config.AuthConfig
	frontendCfg      config.FrontendConfig
	emailService     *email.Service
	securityCfg      config.SecurityConfig
	sessionCache     sessioncache.Store
	geoService        *geolocation.Service
	loginRiskAnalyzer *loginrisk.Analyzer
	captchaVerifier  captchaVerifier
	// SECURITY: In-memory fallback for 2FA rate limiting when Redis is unavailable
	// WARNING: Not suitable for multi-instance deployments (no cross-instance sync)
	memory2FALimiter *memory2FARateLimiter

	// oidcVerifiers caches per-provider OIDC ID-token verifiers. See V3:
	// non-Telegram id_tokens MUST be cryptographically verified — there is
	// no ParseUnverified fallback path anywhere in this handler.
	oidcVerifiers *oidcVerifierCache

	// sendPasswordResetEmail is a test seam. When nil (the production case)
	// the handler dispatches to emailService.SendPasswordResetEmail. Tests
	// override this so they can capture the URL the handler hands to the
	// email layer without spinning up SMTP. Do not set in production.
	sendPasswordResetEmail func(ctx context.Context, to, token, baseURL string) error
}

// NewHandler constructs an auth Handler.
func NewHandler(db *gorm.DB, cfg config.AuthConfig, frontendCfg config.FrontendConfig, emailService *email.Service, securityCfg config.SecurityConfig, cache sessioncache.Store, geoGroup *geolocation.ServiceGroup, loginRiskGroup *loginrisk.ServiceGroup) *Handler {
	if cache == nil {
		cache = sessioncache.NewNoopStore()
	}
	if geoGroup == nil {
		geoGroup = geolocation.NewServiceGroup()
	}
	if loginRiskGroup == nil {
		loginRiskGroup = loginrisk.NewServiceGroup(db)
	}
	return &Handler{
		db:                db,
		cfg:               cfg,
		frontendCfg:       frontendCfg,
		emailService:      emailService,
		securityCfg:       securityCfg,
		sessionCache:      cache,
		geoService:        &geoGroup.Service,
		loginRiskAnalyzer: &loginRiskGroup.Analyzer,
		captchaVerifier:   newCaptchaVerifier(cfg.Captcha.Turnstile),
		memory2FALimiter:  newMemory2FARateLimiter(), // Always create in-memory fallback
		oidcVerifiers:     newOIDCVerifierCache(),
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
	h.RegisterOAuthRoutes(oauth)
}

// RegisterOAuthRoutes binds OAuth-specific routes to the router group.
func (h *Handler) RegisterOAuthRoutes(rg *gin.RouterGroup) {
	rg.POST("/:provider/init", h.InitiateOAuth)
	rg.POST("/:provider/callback", middleware.OptionalAuthMiddleware(h.sessionCache), h.HandleOAuthCallback)
}

package auth

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/geolocation"
	"paigram/internal/sessioncache"
)

// Handler coordinates authentication-related endpoints (email + OAuth).
type Handler struct {
	db           *gorm.DB
	cfg          config.AuthConfig
	emailCfg     config.EmailConfig
	sessionCache sessioncache.Store
	geoService   *geolocation.Service
}

// NewHandler constructs an auth Handler.
func NewHandler(db *gorm.DB, cfg config.AuthConfig, emailCfg config.EmailConfig, cache sessioncache.Store, geoService *geolocation.Service) *Handler {
	if cache == nil {
		cache = sessioncache.NewNoopStore()
	}
	if geoService == nil {
		geoService = geolocation.NewService()
	}
	return &Handler{
		db:           db,
		cfg:          cfg,
		emailCfg:     emailCfg,
		sessionCache: cache,
		geoService:   geoService,
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
	oauth.POST("/telegram", h.HandleTelegramAuth)
	oauth.POST("/:provider/init", h.InitiateOAuth)
	oauth.POST("/:provider/callback", h.HandleOAuthCallback)
}

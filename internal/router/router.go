package router

import (
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/email"
	"paigram/internal/geolocation"
	"paigram/internal/handler"
	authhandler "paigram/internal/handler/auth"
	profilehandler "paigram/internal/handler/profile"
	securityhandler "paigram/internal/handler/security"
	sessionhandler "paigram/internal/handler/session"
	"paigram/internal/middleware"
	"paigram/internal/observability"
	"paigram/internal/response"
	"paigram/internal/sessioncache"
)

// New initialises the Gin router with application routes.
func New(cfg *config.Config, cache sessioncache.Store, db *gorm.DB, rateLimitStore limiter.Store, emailService *email.Service) (*gin.Engine, error) {
	appCfg := cfg.App
	authCfg := cfg.Auth
	rateLimitCfg := cfg.RateLimit

	if appCfg.Mode == "" {
		appCfg.Mode = gin.ReleaseMode
	}
	gin.SetMode(appCfg.Mode)

	engine := gin.New()
	if sentryMiddleware := observability.GinMiddleware(cfg.Sentry); sentryMiddleware != nil {
		engine.Use(sentryMiddleware)
	}
	if scopeMiddleware := observability.GinScopeMiddleware(); scopeMiddleware != nil {
		engine.Use(scopeMiddleware)
	}
	engine.Use(gin.Recovery(), gin.Logger())

	corsMiddleware, err := newCORSMiddleware(appCfg.CORS)
	if err != nil {
		log.Printf("[SECURITY WARNING] Failed to configure CORS middleware: %v", err)
	} else if corsMiddleware != nil {
		engine.Use(corsMiddleware)
		log.Printf("[SECURITY] CORS enabled for %v", appCfg.CORS.AllowOrigins)
	}

	// SECURITY: Configure trusted proxies to prevent IP spoofing
	// This is critical for rate limiting based on IP address
	if len(appCfg.TrustedProxies) > 0 {
		if err := engine.SetTrustedProxies(appCfg.TrustedProxies); err != nil {
			log.Printf("[SECURITY WARNING] Failed to set trusted proxies: %v", err)
			log.Printf("Rate limiting by IP may be vulnerable to spoofing!")
		} else {
			log.Printf("[SECURITY] Trusted proxies configured: %v", appCfg.TrustedProxies)
		}
	} else {
		// No trusted proxies - trust direct connections only
		if err := engine.SetTrustedProxies(nil); err != nil {
			log.Printf("[SECURITY WARNING] Failed to disable trusted proxies: %v", err)
		}
		log.Printf("[SECURITY] No trusted proxies - only direct connections trusted")
	}

	registerSwagger(engine)

	// Initialize handler groups with dependencies
	if err := handler.InitializeApiGroups(db, cache, authCfg); err != nil {
		return nil, fmt.Errorf("initialize api groups: %w", err)
	}

	// swagger:route GET /healthz health healthCheck
	//
	// Health check endpoint.
	//
	// Returns the health status of the service.
	//
	// Produces:
	//   - application/json
	//
	// Responses:
	//   200: healthResponse
	engine.GET("/healthz", func(c *gin.Context) {
		response.Success(c, gin.H{
			"status": "ok",
		})
	})

	api := engine.Group("/api")
	v1 := api.Group("/v1")

	// Initialize geolocation service
	geoService := geolocation.NewService()

	// Public routes - no authentication required
	authHandler := authhandler.NewHandler(db, authCfg, emailService, cfg.Security, cache, geoService)
	authGroup := v1.Group("/auth")
	{
		// Apply rate limiting to auth endpoints if enabled
		if rateLimitCfg.Enabled && rateLimitStore != nil {
			// Register endpoint with rate limiting
			authGroup.POST("/register",
				middleware.RateLimit(middleware.RateLimitConfig{
					Rate:    rateLimitCfg.Auth.Register,
					KeyFunc: middleware.IPKeyFunc,
					Store:   rateLimitStore,
				}),
				authHandler.RegisterEmail,
			)

			// Login endpoint with rate limiting
			authGroup.POST("/login",
				middleware.RateLimit(middleware.RateLimitConfig{
					Rate:    rateLimitCfg.Auth.Login,
					KeyFunc: middleware.IPKeyFunc,
					Store:   rateLimitStore,
				}),
				authHandler.LoginWithEmail,
			)

			// Refresh token endpoint with rate limiting
			authGroup.POST("/refresh",
				middleware.RateLimit(middleware.RateLimitConfig{
					Rate:    rateLimitCfg.Auth.RefreshToken,
					KeyFunc: middleware.IPKeyFunc,
					Store:   rateLimitStore,
				}),
				authHandler.RefreshToken,
			)

			// Verify email endpoint with rate limiting (by email)
			authGroup.POST("/verify-email",
				middleware.RateLimit(middleware.RateLimitConfig{
					Rate:    rateLimitCfg.Auth.VerifyEmail,
					KeyFunc: middleware.EmailKeyFunc("email"),
					Store:   rateLimitStore,
				}),
				authHandler.VerifyEmail,
			)

			// Password reset request endpoint with rate limiting (by email)
			authGroup.POST("/forgot-password",
				middleware.RateLimit(middleware.RateLimitConfig{
					Rate:    rateLimitCfg.Auth.VerifyEmail,
					KeyFunc: middleware.EmailKeyFunc("email"),
					Store:   rateLimitStore,
				}),
				authHandler.ForgotPassword,
			)

			// Password reset completion endpoint with rate limiting (by IP)
			authGroup.POST("/reset-password",
				middleware.RateLimit(middleware.RateLimitConfig{
					Rate:    rateLimitCfg.API.Unauthenticated,
					KeyFunc: middleware.IPKeyFunc,
					Store:   rateLimitStore,
				}),
				authHandler.ResetPassword,
			)

			// Logout doesn't need strict rate limiting
			authGroup.POST("/logout", authHandler.Logout)

			// OAuth routes with rate limiting
			oauth := authGroup.Group("/oauth")
			oauth.Use(middleware.RateLimit(middleware.RateLimitConfig{
				Rate:    rateLimitCfg.Auth.OAuth,
				KeyFunc: middleware.IPKeyFunc,
				Store:   rateLimitStore,
			}))
			{
				oauth.POST("/:provider/init", authHandler.InitiateOAuth)
				oauth.POST("/:provider/callback", authHandler.HandleOAuthCallback)
			}
		} else {
			// No rate limiting - register routes normally
			authHandler.RegisterRoutes(authGroup)
		}
	}

	// Protected routes - require authentication
	protected := v1.Group("")
	protected.Use(middleware.AuthMiddleware(cache, authCfg))

	// Apply rate limiting to authenticated endpoints if enabled
	if rateLimitCfg.Enabled && rateLimitStore != nil {
		protected.Use(middleware.RateLimit(middleware.RateLimitConfig{
			Rate:    rateLimitCfg.API.Authenticated,
			KeyFunc: middleware.UserIDKeyFunc,
			Store:   rateLimitStore,
		}))
	}

	// User, authority, and casbin policy routes - delegated to router groups
	InitializeRouterGroups(protected, db)

	// Profile management routes
	profileHandler := profilehandler.NewHandler(db, authCfg)
	profiles := protected.Group("/profiles")
	{
		// Get profile - self or requires user:read permission
		profiles.GET("/:id", middleware.SelfOrCasbinPermission(), profileHandler.GetProfile)

		// Update profile - self or requires user:write permission
		profiles.PATCH("/:id", middleware.SelfOrCasbinPermission(), profileHandler.UpdateProfile)

		// Account binding - only self can manage
		profiles.GET("/:id/accounts", middleware.RequireSelf(), profileHandler.GetBoundAccounts)
		profiles.POST("/:id/accounts/bind", middleware.RequireSelf(), profileHandler.BindAccount)
		profiles.DELETE("/:id/accounts/:provider", middleware.RequireSelf(), profileHandler.UnbindAccount)
	}

	// Email management routes - only self can manage their own emails
	// We need to create a separate group to apply RequireSelf middleware
	emailGroup := protected.Group("/profiles")
	emailGroup.Use(middleware.RequireSelf())
	profileHandler.RegisterEmailRoutes(emailGroup)

	// Security routes (password change, 2FA) - only self + fresh session for sensitive ops
	securityHandler := securityhandler.NewHandler(db, cache, cfg.Security)
	security := protected.Group("/profiles")
	security.Use(middleware.RequireSelf())
	{
		// Routes that DON'T require fresh session
		security.GET("/:id/devices", securityHandler.GetDevices)

		// Routes that REQUIRE fresh session (sensitive operations)
		freshSecurity := security.Group("")
		freshSecurity.Use(middleware.RequireFreshSession(authCfg))
		{
			freshSecurity.POST("/:id/password/change", securityHandler.ChangePassword)
			freshSecurity.POST("/:id/2fa/enable", securityHandler.Enable2FA)
			freshSecurity.POST("/:id/2fa/confirm", securityHandler.Confirm2FA)
			freshSecurity.POST("/:id/2fa/disable", securityHandler.Disable2FA)
			freshSecurity.POST("/:id/2fa/regenerate-backup-codes", securityHandler.RegenerateBackupCodes)
			freshSecurity.DELETE("/:id/devices/:device_id", securityHandler.RemoveDevice)
		}
	}

	// Session management routes
	sessionHandler := sessionhandler.NewHandler(db, cache)
	sessions := protected.Group("/sessions")
	{
		sessionHandler.RegisterRoutes(sessions)
	}

	// swagger:route GET / general getRoot
	//
	// Root endpoint.
	//
	// Returns basic service information.
	//
	// Produces:
	//   - application/json
	//
	// Responses:
	//   200: rootResponse
	engine.GET("/", func(c *gin.Context) {
		response.Success(c, gin.H{
			"message": fmt.Sprintf("%s is running", appCfg.Name),
		})
	})

	return engine, nil
}

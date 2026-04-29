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

	// V10: emit baseline security response headers BEFORE CORS so they
	// are present even on CORS-rejected and error responses.
	engine.Use(middleware.SecurityHeaders(middleware.SecurityHeadersConfig{
		HSTSMaxAgeSeconds: cfg.Security.SecurityHeaders.HSTSMaxAgeSeconds,
		HSTSIncludeSub:    cfg.Security.SecurityHeaders.HSTSIncludeSub,
		CSP:               cfg.Security.SecurityHeaders.CSP,
		AssumeHTTPS:       cfg.Security.SecurityHeaders.AssumeHTTPS,
	}))

	corsMiddleware, err := newCORSMiddleware(appCfg.CORS)
	if err != nil {
		log.Printf("[SECURITY WARNING] Failed to configure CORS middleware: %v", err)
	} else if corsMiddleware != nil {
		engine.Use(corsMiddleware)
		log.Printf("[SECURITY] CORS enabled for %v", appCfg.CORS.AllowOrigins)
	}

	// SECURITY: Configure trusted proxies to prevent IP spoofing.
	// V21: trusted_proxies defaults to empty (fail-safe). Operators
	// behind a reverse proxy MUST configure their proxy IP/CIDR or
	// X-Forwarded-For-based rate limiting will be spoofable.
	if len(appCfg.TrustedProxies) > 0 {
		if err := engine.SetTrustedProxies(appCfg.TrustedProxies); err != nil {
			log.Printf("[SECURITY WARNING] Failed to set trusted proxies: %v", err)
			log.Printf("Rate limiting by IP may be vulnerable to spoofing!")
		} else {
			log.Printf("[security] app.trusted_proxies = %v", appCfg.TrustedProxies)
		}
	} else {
		// No trusted proxies — gin will use the direct connection IP.
		// Correct for direct deployments; operators behind a reverse
		// proxy must set app.trusted_proxies explicitly.
		if err := engine.SetTrustedProxies(nil); err != nil {
			log.Printf("[SECURITY WARNING] Failed to disable trusted proxies: %v", err)
		}
		log.Printf("[security] app.trusted_proxies is empty — gin will trust only the direct client connection IP. " +
			"If running behind a reverse proxy, set app.trusted_proxies to its real IP/CIDR.")
	}

	registerSwagger(engine)

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

	// Initialize handler groups with dependencies
	if err := handler.InitializeApiGroups(db, cache, authCfg, cfg.Security); err != nil {
		return nil, fmt.Errorf("initialize api groups: %w", err)
	}
	handler.ApiGroupApp.AuthApiGroup = *authhandler.NewApiGroup(db, authCfg, cfg.Frontend, emailService, cfg.Security, cache, geoService)

	// Public routes - no authentication required
	authHandler := &handler.ApiGroupApp.AuthApiGroup.Handler
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
				authHandler.RegisterOAuthRoutes(oauth)
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
	InitializeRouterGroups(protected, db, authCfg)

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

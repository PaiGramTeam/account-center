package router

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	"gorm.io/gorm"

	"paigram/internal/config"
	authhandler "paigram/internal/handler/auth"
	profilehandler "paigram/internal/handler/profile"
	securityhandler "paigram/internal/handler/security"
	userhandler "paigram/internal/handler/user"
	"paigram/internal/middleware"
	"paigram/internal/model"
	"paigram/internal/permission"
	"paigram/internal/response"
	"paigram/internal/sessioncache"
)

// New initialises the Gin router with application routes.
func New(cfg *config.Config, cache sessioncache.Store, db *gorm.DB, rateLimitStore limiter.Store) *gin.Engine {
	appCfg := cfg.App
	authCfg := cfg.Auth
	rateLimitCfg := cfg.RateLimit

	if appCfg.Mode == "" {
		appCfg.Mode = gin.ReleaseMode
	}
	gin.SetMode(appCfg.Mode)

	engine := gin.New()
	engine.Use(gin.Recovery(), gin.Logger())

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

	// Public routes - no authentication required
	authHandler := authhandler.NewHandler(db, authCfg, cfg.Email, cache)
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
				oauth.POST("/telegram", authHandler.HandleTelegramAuth)
				oauth.POST("/:provider/init", authHandler.InitiateOAuth)
				oauth.POST("/:provider/callback", authHandler.HandleOAuthCallback)
			}
		} else {
			// No rate limiting - register routes normally
			authHandler.RegisterRoutes(authGroup)
		}
	}

	// Initialize permission manager
	permMgr := permission.NewManager(db)

	// Protected routes - require authentication
	protected := v1.Group("")
	protected.Use(middleware.AuthMiddleware(db, cache))

	// Apply rate limiting to authenticated endpoints if enabled
	if rateLimitCfg.Enabled && rateLimitStore != nil {
		protected.Use(middleware.RateLimit(middleware.RateLimitConfig{
			Rate:    rateLimitCfg.API.Authenticated,
			KeyFunc: middleware.UserIDKeyFunc,
			Store:   rateLimitStore,
		}))
	}

	// User management routes
	userHandler := userhandler.NewHandler(db)
	users := protected.Group("/users")
	{
		// List users - requires user:read permission
		users.GET("", middleware.PermissionMiddleware(permMgr, model.PermUserRead), userHandler.ListUsers)

		// Create user - requires user:write permission
		users.POST("", middleware.PermissionMiddleware(permMgr, model.PermUserWrite), userHandler.CreateUser)

		// Get user - self or requires user:read permission
		users.GET("/:id", middleware.SelfOrPermission(permMgr, model.PermUserRead), userHandler.GetUser)

		// Update user - self or requires user:write permission
		users.PATCH("/:id", middleware.SelfOrPermission(permMgr, model.PermUserWrite), userHandler.UpdateUser)

		// Delete user - requires user:delete permission
		users.DELETE("/:id", middleware.PermissionMiddleware(permMgr, model.PermUserDelete), userHandler.DeleteUser)

		// Update user status - requires admin role
		users.PATCH("/:id/status", middleware.AdminMiddleware(permMgr), userHandler.UpdateUserStatus)

		// Reset user password - requires admin role
		users.POST("/:id/reset-password", middleware.AdminMiddleware(permMgr), userHandler.ResetUserPassword)

		// Get audit logs - self or requires audit:read permission
		users.GET("/:id/audit-logs", middleware.SelfOrPermission(permMgr, model.PermAuditRead), userHandler.GetAuditLogs)

		// Get user roles - self or requires role:read permission
		users.GET("/:id/roles", middleware.SelfOrPermission(permMgr, model.PermRoleRead), userHandler.GetUserRoles)

		// Get user permissions - self or requires permission:read permission
		users.GET("/:id/permissions", middleware.SelfOrPermission(permMgr, model.PermPermissionRead), userHandler.GetUserPermissions)
	}

	// Login log routes (under /users path)
	userHandler.RegisterLoginLogRoutes(protected.Group("/users"))

	// Profile management routes
	profileHandler := profilehandler.NewHandler(db, authCfg)
	profiles := protected.Group("/profiles")
	{
		// Get profile - self or requires user:read permission
		profiles.GET("/:id", middleware.SelfOrPermission(permMgr, model.PermUserRead), profileHandler.GetProfile)

		// Update profile - self or requires user:write permission
		profiles.PATCH("/:id", middleware.SelfOrPermission(permMgr, model.PermUserWrite), profileHandler.UpdateProfile)

		// Account binding - only self can manage
		profiles.GET("/:id/accounts", middleware.RequireSelf(), profileHandler.GetBoundAccounts)
		profiles.POST("/:id/accounts/bind", middleware.RequireSelf(), profileHandler.BindAccount)
		profiles.DELETE("/:id/accounts/:provider", middleware.RequireSelf(), profileHandler.UnbindAccount)
	}

	// Email management routes - only self can manage their own emails
	// We need to create a separate group to apply RequireSelf middleware
	emailGroup := protected.Group("/profiles/:id/emails")
	emailGroup.Use(middleware.RequireSelf())
	profileHandler.RegisterEmailRoutes(emailGroup)

	// Security routes (password change, 2FA) - only self
	securityHandler := securityhandler.NewHandler(db, cache)
	security := protected.Group("/profiles/:id")
	security.Use(middleware.RequireSelf())
	{
		securityHandler.RegisterRoutes(security)
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

	return engine
}

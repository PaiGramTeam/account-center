package router

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/config"
	authhandler "paigram/internal/handler/auth"
	profilehandler "paigram/internal/handler/profile"
	securityhandler "paigram/internal/handler/security"
	userhandler "paigram/internal/handler/user"
	"paigram/internal/response"
	"paigram/internal/sessioncache"
)

// New initialises the Gin router with application routes.
func New(appCfg config.AppConfig, authCfg config.AuthConfig, cache sessioncache.Store, db *gorm.DB) *gin.Engine {
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

	authHandler := authhandler.NewHandler(db, authCfg, cache)
	authHandler.RegisterRoutes(v1.Group("/auth"))

	userHandler := userhandler.NewHandler(db)
	userHandler.RegisterRoutes(v1.Group("/users"))
	userHandler.RegisterLoginLogRoutes(v1.Group("/users"))

	profileHandler := profilehandler.NewHandler(db, authCfg)
	profileHandler.RegisterRoutes(v1.Group("/profiles"))

	securityHandler := securityhandler.NewHandler(db)
	securityHandler.RegisterRoutes(v1.Group("/profiles"))

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

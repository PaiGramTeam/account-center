package router

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/config"
	authhandler "paigram/internal/handler/auth"
	profilehandler "paigram/internal/handler/profile"
	userhandler "paigram/internal/handler/user"
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

	engine.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	api := engine.Group("/api")
	v1 := api.Group("/v1")

	authHandler := authhandler.NewHandler(db, authCfg, cache)
	authHandler.RegisterRoutes(v1.Group("/auth"))

	userHandler := userhandler.NewHandler(db)
	userHandler.RegisterRoutes(v1.Group("/users"))

	profileHandler := profilehandler.NewHandler(db)
	profileHandler.RegisterRoutes(v1.Group("/profiles"))

	engine.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": fmt.Sprintf("%s is running", appCfg.Name),
		})
	})

	return engine
}

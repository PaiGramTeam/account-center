package main

import (
	"fmt"
	"log"

	"github.com/redis/go-redis/v9"

	"paigram/internal/cache"
	"paigram/internal/config"
	"paigram/internal/database"
	"paigram/internal/logging"
	"paigram/internal/router"
	"paigram/internal/sessioncache"
)

func main() {
	cfg := config.MustLoad("config")
	defer logging.Sync()

	db := database.MustConnect(cfg.Database)

	var sessionStore sessioncache.Store = sessioncache.NewNoopStore()
	var redisClient *redis.Client
	if cfg.Redis.Enabled {
		client, err := cache.NewRedisClient(cfg.Redis)
		if err != nil {
			log.Fatalf("redis connection failed: %v", err)
		}
		redisClient = client
		sessionStore = sessioncache.NewRedisStore(client, cfg.Redis.Prefix)
		defer redisClient.Close()
	}

	engine := router.New(cfg.App, cfg.Auth, sessionStore, db)

	addr := fmt.Sprintf("%s:%d", cfg.App.Host, cfg.App.Port)
	if err := engine.Run(addr); err != nil {
		log.Fatalf("gin server failed: %v", err)
	}
}

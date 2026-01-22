package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/redis/go-redis/v9"

	"paigram/internal/cache"
	"paigram/internal/config"
	"paigram/internal/database"
	"paigram/internal/grpc/server"
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

	// Create wait group for graceful shutdown
	var wg sync.WaitGroup

	// Start gRPC server if enabled
	if cfg.GRPC.Enabled {
		grpcServer := server.NewGRPCServer(cfg.GRPC.Port, db)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := grpcServer.Start(); err != nil {
				log.Printf("gRPC server error: %v", err)
			}
		}()
		log.Printf("gRPC server started on port %d", cfg.GRPC.Port)
	}

	// Start HTTP server
	engine := router.New(cfg.App, cfg.Auth, sessionStore, db)
	addr := fmt.Sprintf("%s:%d", cfg.App.Host, cfg.App.Port)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := engine.Run(addr); err != nil {
			log.Printf("HTTP server error: %v", err)
		}
	}()
	log.Printf("HTTP server started on %s", addr)

	// Wait for all servers to complete
	wg.Wait()
}

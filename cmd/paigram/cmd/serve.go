package cmd

import (
	"fmt"
	"log"
	"sync"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/cobra"
	"github.com/ulule/limiter/v3"
	"gorm.io/gorm"

	"paigram/internal/cache"
	"paigram/internal/config"
	"paigram/internal/database"
	"paigram/internal/grpc/server"
	"paigram/internal/logging"
	"paigram/internal/middleware"
	"paigram/internal/router"
	"paigram/internal/sessioncache"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Paigram server",
	Long: `Start the Paigram server with HTTP and gRPC services.
	
This command starts both the HTTP REST API server and the gRPC server
(if enabled) to provide authentication and user management services.`,
	Run: func(cmd *cobra.Command, args []string) {
		runServer()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().String("host", "", "Server host (overrides config)")
	serveCmd.Flags().Int("port", 0, "Server port (overrides config)")
	serveCmd.Flags().Bool("grpc", true, "Enable gRPC server")
}

func runServer() {
	cfg := config.MustLoad("config")
	defer logging.Sync()

	db := database.MustConnect(cfg.Database)

	var sessionStore sessioncache.Store = sessioncache.NewNoopStore()
	var redisClient *redis.Client
	var rateLimitStore limiter.Store
	if cfg.Redis.Enabled {
		client, err := cache.NewRedisClient(cfg.Redis)
		if err != nil {
			log.Fatalf("redis connection failed: %v", err)
		}
		redisClient = client
		sessionStore = sessioncache.NewRedisStore(client, cfg.Redis.Prefix)

		// Initialize rate limit store if rate limiting is enabled
		if cfg.RateLimit.Enabled {
			rateLimitStore, err = middleware.NewRedisStore(client, cfg.Redis.Prefix+":ratelimit")
			if err != nil {
				log.Fatalf("rate limit store initialization failed: %v", err)
			}
		}

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
	engine := router.New(cfg, sessionStore, db, rateLimitStore)
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

// getDB helper function to get database connection for CLI commands
func getDB() *gorm.DB {
	cfg := config.MustLoad("config")
	// Disable auto initialization for CLI commands
	cfg.Database.AutoMigrate = false
	cfg.Database.AutoSeed = false
	return database.MustConnect(cfg.Database)
}

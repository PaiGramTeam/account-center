package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	sentry "github.com/getsentry/sentry-go"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/cobra"
	"github.com/ulule/limiter/v3"
	"gorm.io/gorm"

	"paigram/internal/cache"
	"paigram/internal/config"
	"paigram/internal/crypto"
	"paigram/internal/database"
	"paigram/internal/email"
	"paigram/internal/geolocation"
	"paigram/internal/grpc/server"
	authhandler "paigram/internal/handler/auth"
	"paigram/internal/logging"
	"paigram/internal/middleware"
	"paigram/internal/observability"
	"paigram/internal/router"
	"paigram/internal/sessioncache"
	"paigram/internal/worker"
)

type httpShutdowner interface {
	Shutdown(ctx context.Context) error
}

type grpcStopper interface {
	Stop()
}

type shutdowner interface {
	Shutdown()
}

type closer interface {
	Close() error
}

type shutdownTargets struct {
	httpServer     httpShutdowner
	grpcServer     grpcStopper
	asynqServer    shutdowner
	asynqScheduler shutdowner
	emailService   closer
}

func shutdownServices(ctx context.Context, targets shutdownTargets) error {
	var errs []error

	if targets.httpServer != nil {
		if err := targets.httpServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("shutdown http server: %w", err))
		}
	}

	if targets.grpcServer != nil {
		targets.grpcServer.Stop()
	}

	if targets.asynqServer != nil {
		targets.asynqServer.Shutdown()
	}

	if targets.asynqScheduler != nil {
		targets.asynqScheduler.Shutdown()
	}

	if targets.emailService != nil {
		if err := targets.emailService.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close email service: %w", err))
		}
	}

	return errors.Join(errs...)
}

func fatalStartup(cfg config.SentryConfig, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	observability.CaptureMessage(message, func(scope *sentry.Scope) {
		scope.SetTag("component", "startup")
	})
	observability.Flush(cfg)
	log.Fatalf("%s", message)
}

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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := config.MustLoad("config")
	if err := observability.Init(cfg.Sentry); err != nil {
		log.Fatalf("sentry initialization failed: %v", err)
	}
	defer logging.Sync()

	// Initialize encryption for 2FA secrets
	if err := crypto.InitEncryption(); err != nil {
		log.Printf("WARNING: Encryption initialization failed: %v", err)
		log.Printf("2FA will not work properly. Please set ENCRYPTION_KEY environment variable.")
	}

	db, err := database.Connect(cfg.Database)
	if err != nil {
		fatalStartup(cfg.Sentry, "database connection failed: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		fatalStartup(cfg.Sentry, "database handle initialization failed: %v", err)
	}
	defer sqlDB.Close()

	var sessionStore sessioncache.Store = sessioncache.NewNoopStore()
	var redisClient *redis.Client
	var rateLimitStore limiter.Store
	if cfg.Redis.Enabled {
		client, err := cache.NewRedisClient(cfg.Redis)
		if err != nil {
			fatalStartup(cfg.Sentry, "redis connection failed: %v", err)
		}
		redisClient = client
		sessionStore = sessioncache.NewRedisStore(client, cfg.Redis.Prefix)

		// Initialize rate limit store if rate limiting is enabled
		if cfg.RateLimit.Enabled {
			rateLimitStore, err = middleware.NewRedisStore(client, cfg.Redis.Prefix+":ratelimit")
			if err != nil {
				fatalStartup(cfg.Sentry, "rate limit store initialization failed: %v", err)
			}
		}
	}

	// Initialize email service singleton
	var emailService *email.Service
	if redisClient != nil {
		emailService, err = email.NewServiceWithRedis(cfg.Email, redisClient)
	} else {
		emailService, err = email.NewService(cfg.Email)
	}
	if err != nil {
		fatalStartup(cfg.Sentry, "email service initialization failed: %v", err)
	}

	// Start email queue if async is enabled
	if cfg.Email.UseAsyncQueue {
		if err := emailService.StartQueue(ctx); err != nil {
			fatalStartup(cfg.Sentry, "failed to start email queue: %v", err)
		}
		log.Printf("Email queue started (backend: %s)", cfg.Email.QueueBackend)
	}

	// Create wait group for graceful shutdown
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	var httpServer *http.Server
	var grpcServer *server.GRPCServer
	var asynqServer shutdowner
	var asynqScheduler shutdowner
	shutdown := sync.OnceFunc(func() {
		log.Println("Shutting down services...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := shutdownServices(shutdownCtx, shutdownTargets{
			httpServer:     httpServer,
			grpcServer:     grpcServer,
			asynqServer:    asynqServer,
			asynqScheduler: asynqScheduler,
			emailService:   emailService,
		}); err != nil {
			log.Printf("Graceful shutdown completed with errors: %v", err)
		}
		if redisClient != nil {
			if err := redisClient.Close(); err != nil {
				log.Printf("Redis close error: %v", err)
			}
		}
		if !observability.Flush(cfg.Sentry) {
			log.Printf("Sentry flush timed out after %d seconds", cfg.Sentry.FlushTimeout)
		}
	})

	// Start gRPC server if enabled
	if cfg.GRPC.Enabled {
		grpcServer = server.NewGRPCServer(cfg.GRPC.Port, db, redisClient, cfg)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := grpcServer.Start(); err != nil {
				errCh <- fmt.Errorf("gRPC server: %w", err)
			}
		}()
		log.Printf("gRPC server started on port %d", cfg.GRPC.Port)
	}

	// Start Asynq worker for background tasks (OAuth token refresh, etc.)
	if cfg.Redis.Enabled {
		// Create auth handler for worker
		geoService := geolocation.NewService()
		authHandler := authhandler.NewHandler(db, cfg.Auth, emailService, cfg.Security, sessionStore, geoService)

		asynqServer, asynqScheduler, err = worker.StartAsynqServer(cfg, redisClient, db, authHandler)
		if err != nil {
			log.Printf("WARNING: Failed to start Asynq worker: %v", err)
			log.Println("Background tasks (OAuth token refresh) will not run")
		}
	}

	// Start HTTP server
	engine := router.New(cfg, sessionStore, db, rateLimitStore, emailService)
	addr := fmt.Sprintf("%s:%d", cfg.App.Host, cfg.App.Port)
	httpServer = &http.Server{
		Addr:    addr,
		Handler: engine,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("HTTP server: %w", err)
		}
	}()
	log.Printf("HTTP server started on %s", addr)

	select {
	case <-ctx.Done():
		log.Printf("Received shutdown signal: %v", ctx.Err())
	case err := <-errCh:
		log.Printf("Server exited with error: %v", err)
	}

	shutdown()
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

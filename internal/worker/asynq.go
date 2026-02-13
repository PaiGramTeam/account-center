package worker

import (
	"context"
	"log"
	"time"

	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/handler/auth"
	"paigram/internal/tasks"
)

// StartAsynqServer starts the asynq worker server and scheduler
func StartAsynqServer(cfg *config.Config, redisClient *redis.Client, db *gorm.DB, authHandler *auth.Handler) (*asynq.Server, *asynq.Scheduler, error) {
	if !cfg.Redis.Enabled {
		log.Println("[Asynq] Redis not enabled, skipping worker startup")
		return nil, nil, nil
	}

	// Create asynq client for enqueuing tasks
	asynqClient := asynq.NewClient(asynq.RedisClientOpt{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	// Create task handlers
	refreshHandler := tasks.NewRefreshOAuthTokenHandler(db, cfg, authHandler)
	scheduleHandler := tasks.NewScheduleOAuthRefreshHandler(db, cfg, asynqClient)
	cleanupHandler := tasks.NewCleanExpiredOAuthStatesHandler(db)

	// Create mux (task router)
	mux := asynq.NewServeMux()
	mux.HandleFunc(tasks.TypeRefreshOAuthToken, refreshHandler.ProcessTask)
	mux.HandleFunc(tasks.TypeScheduleOAuthRefresh, scheduleHandler.ProcessTask)
	mux.HandleFunc(tasks.TypeCleanExpiredOAuthStates, cleanupHandler.ProcessTask)

	// Configure server
	srv := asynq.NewServer(
		asynq.RedisClientOpt{
			Addr:     cfg.Redis.Addr,
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
		},
		asynq.Config{
			Concurrency: 10, // Number of concurrent workers
			Queues: map[string]int{
				"critical": 6, // 60% of workers
				"default":  3, // 30% of workers
				"low":      1, // 10% of workers
			},
			StrictPriority: false, // Don't starve low-priority queues
			// Error handler
			ErrorHandler: asynq.ErrorHandlerFunc(func(ctx context.Context, task *asynq.Task, err error) {
				log.Printf("[Asynq] Task failed: type=%s, payload=%s, error=%v",
					task.Type(), string(task.Payload()), err)
			}),
			// Logger
			LogLevel: asynq.InfoLevel,
		},
	)

	// Create scheduler for periodic tasks
	scheduler := asynq.NewScheduler(
		asynq.RedisClientOpt{
			Addr:     cfg.Redis.Addr,
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
		},
		&asynq.SchedulerOpts{
			LogLevel: asynq.InfoLevel,
		},
	)

	// Register periodic task: check for expiring tokens every hour
	scheduleTask, err := tasks.NewScheduleOAuthRefreshTask()
	if err != nil {
		return nil, nil, err
	}

	// Schedule to run every hour
	entryID, err := scheduler.Register("@hourly", scheduleTask)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("[Asynq] Registered periodic task: schedule_oauth_refresh (entry_id=%s)", entryID)

	// Register periodic task: clean expired OAuth states every 6 hours
	cleanupTask, err := tasks.NewCleanExpiredOAuthStatesTask()
	if err != nil {
		return nil, nil, err
	}

	entryID2, err := scheduler.Register("0 */6 * * *", cleanupTask) // Every 6 hours
	if err != nil {
		return nil, nil, err
	}
	log.Printf("[Asynq] Registered periodic task: clean_expired_oauth_states (entry_id=%s)", entryID2)

	// Start server in background
	go func() {
		log.Println("[Asynq] Worker server starting...")
		if err := srv.Run(mux); err != nil {
			log.Fatalf("[Asynq] Server error: %v", err)
		}
	}()

	// Start scheduler in background
	go func() {
		log.Println("[Asynq] Scheduler starting...")
		if err := scheduler.Run(); err != nil {
			log.Fatalf("[Asynq] Scheduler error: %v", err)
		}
	}()

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)
	log.Println("[Asynq] Worker and scheduler started successfully")

	return srv, scheduler, nil
}

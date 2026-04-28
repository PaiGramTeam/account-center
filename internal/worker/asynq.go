package worker

import (
	"context"
	"log"

	sentry "github.com/getsentry/sentry-go"
	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/handler/auth"
	"paigram/internal/observability"
	serviceplatform "paigram/internal/service/platform"
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
	platformService := serviceplatform.NewServiceGroup(db)
	if err := platformService.PlatformService.ConfigureAuth(cfg.Auth); err != nil {
		return nil, nil, err
	}
	platformService.PlatformService.SetGenericSummaryProxy(serviceplatform.NewGRPCGenericSummaryProxy(nil))
	refreshHandler := tasks.NewRefreshOAuthTokenHandler(db, cfg, authHandler)
	scheduleHandler := tasks.NewScheduleOAuthRefreshHandler(db, cfg, asynqClient)
	cleanupHandler := tasks.NewCleanExpiredOAuthStatesHandler(db)
	botTokenCleanupHandler := tasks.NewCleanExpiredBotTokensHandler(db)
	bindingReconcileHandler := tasks.NewPlatformBindingReconcileHandler(db, asynqClient)
	bindingProjectionRepairHandler := tasks.NewPlatformBindingProjectionRepairHandler(db, &platformService.PlatformService)
	bindingDeleteRepairHandler := tasks.NewPlatformBindingDeleteRepairHandler(db, &platformService.PlatformService)

	// Create mux (task router)
	mux := asynq.NewServeMux()
	mux.HandleFunc(tasks.TypeRefreshOAuthToken, refreshHandler.ProcessTask)
	mux.HandleFunc(tasks.TypeScheduleOAuthRefresh, scheduleHandler.ProcessTask)
	mux.HandleFunc(tasks.TypeCleanExpiredOAuthStates, cleanupHandler.ProcessTask)
	mux.HandleFunc(tasks.TypeCleanExpiredBotTokens, botTokenCleanupHandler.ProcessTask)
	mux.HandleFunc(tasks.TypePlatformBindingReconcile, bindingReconcileHandler.ProcessTask)
	mux.HandleFunc(tasks.TypePlatformBindingProjectionRepair, bindingProjectionRepairHandler.ProcessTask)
	mux.HandleFunc(tasks.TypePlatformBindingDeleteRepair, bindingDeleteRepairHandler.ProcessTask)

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
				observability.CaptureException(err, func(scope *sentry.Scope) {
					scope.SetTag("component", "asynq")
					scope.SetTag("task.type", task.Type())
					scope.SetExtra("task.payload", string(task.Payload()))
					if retryCount, ok := asynq.GetRetryCount(ctx); ok {
						scope.SetExtra("task.retry_count", retryCount)
					}
					if maxRetry, ok := asynq.GetMaxRetry(ctx); ok {
						scope.SetExtra("task.max_retry", maxRetry)
					}
					if queueName, ok := asynq.GetQueueName(ctx); ok {
						scope.SetTag("task.queue", queueName)
					}
				})
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

	// Register periodic task: clean expired bot tokens every 12 hours
	botTokenCleanupTask, err := tasks.NewCleanExpiredBotTokensTask()
	if err != nil {
		return nil, nil, err
	}

	entryID3, err := scheduler.Register("0 */12 * * *", botTokenCleanupTask) // Every 12 hours
	if err != nil {
		return nil, nil, err
	}
	log.Printf("[Asynq] Registered periodic task: clean_expired_bot_tokens (entry_id=%s)", entryID3)

	bindingReconcileTask, err := tasks.NewPlatformBindingReconcileTask()
	if err != nil {
		return nil, nil, err
	}

	entryID4, err := scheduler.Register("0 * * * *", bindingReconcileTask)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("[Asynq] Registered periodic task: platform_binding_reconcile (entry_id=%s)", entryID4)

	log.Println("[Asynq] Worker server starting...")
	if err := srv.Start(mux); err != nil {
		return nil, nil, err
	}

	log.Println("[Asynq] Scheduler starting...")
	if err := scheduler.Start(); err != nil {
		srv.Shutdown()
		return nil, nil, err
	}

	log.Println("[Asynq] Worker and scheduler started successfully")

	return srv, scheduler, nil
}

package email

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"paigram/internal/config"
	"paigram/internal/logging"
)

// RedisQueue implements Queue interface using Redis for persistence
type RedisQueue struct {
	rdb         *redis.Client
	sender      Sender
	cfg         config.EmailConfig
	stopCh      chan struct{}
	workerCount int
}

// Priority queue keys in Redis
const (
	queueKeyCritical = "email:queue:critical"
	queueKeyHigh     = "email:queue:high"
	queueKeyNormal   = "email:queue:normal"
	queueKeyLow      = "email:queue:low"
	queueKeyDLQ      = "email:queue:dlq" // Dead Letter Queue
)

// RedisMessage wraps Message with metadata for Redis storage
type RedisMessage struct {
	Message   *Message  `json:"message"`
	EnqueueAt time.Time `json:"enqueue_at"`
	Attempts  int       `json:"attempts"`
	LastError string    `json:"last_error,omitempty"`
}

// NewRedisQueue creates a new Redis-backed queue
func NewRedisQueue(rdb *redis.Client, sender Sender, cfg config.EmailConfig) *RedisQueue {
	workerCount := 3 // Default worker count
	if cfg.QueueSize > 0 {
		// Use queue size as hint for worker count (max 10)
		workerCount = min(cfg.QueueSize/100, 10)
		if workerCount < 1 {
			workerCount = 1
		}
	}

	return &RedisQueue{
		rdb:         rdb,
		sender:      sender,
		cfg:         cfg,
		stopCh:      make(chan struct{}),
		workerCount: workerCount,
	}
}

// Enqueue adds a message to the Redis queue based on priority
func (q *RedisQueue) Enqueue(ctx context.Context, msg *Message) error {
	redisMsg := &RedisMessage{
		Message:   msg,
		EnqueueAt: time.Now().UTC(),
		Attempts:  0,
	}

	data, err := json.Marshal(redisMsg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	// Determine queue key based on priority
	queueKey := q.getQueueKey(msg.Priority)

	// Push to the left (LPUSH) so we pop from right (RPOP) - FIFO within priority
	if err := q.rdb.LPush(ctx, queueKey, data).Err(); err != nil {
		return fmt.Errorf("enqueue to redis: %w", err)
	}

	// Update queue size metric
	q.updateQueueMetrics(ctx)

	logging.Debug("message enqueued to redis",
		zap.String("queue", queueKey),
		zap.Strings("to", msg.To),
		zap.String("subject", msg.Subject),
	)

	return nil
}

// Start begins processing messages from Redis queues
func (q *RedisQueue) Start(ctx context.Context) error {
	logging.Info("starting redis email queue workers",
		zap.Int("worker_count", q.workerCount),
	)

	// Start multiple workers
	for i := 0; i < q.workerCount; i++ {
		go q.worker(ctx, i)
	}

	// Start metrics updater
	go q.metricsUpdater(ctx)

	return nil
}

// Stop gracefully stops the queue processing
func (q *RedisQueue) Stop() error {
	close(q.stopCh)
	logging.Info("redis email queue stopped")
	return nil
}

// worker processes messages from Redis queues
func (q *RedisQueue) worker(ctx context.Context, workerID int) {
	logging.Info("redis queue worker started", zap.Int("worker_id", workerID))

	// Priority order: Critical > High > Normal > Low
	queues := []string{
		queueKeyCritical,
		queueKeyHigh,
		queueKeyNormal,
		queueKeyLow,
	}

	for {
		select {
		case <-q.stopCh:
			logging.Info("redis queue worker stopped", zap.Int("worker_id", workerID))
			return
		case <-ctx.Done():
			logging.Info("redis queue worker context cancelled", zap.Int("worker_id", workerID))
			return
		default:
			// BRPOP with 1 second timeout to allow checking stop signal
			result, err := q.rdb.BRPop(ctx, 1*time.Second, queues...).Result()
			if err != nil {
				if err == redis.Nil {
					// Timeout, no message available - this is normal
					continue
				}
				logging.Error("redis brpop error",
					zap.Int("worker_id", workerID),
					zap.Error(err),
				)
				time.Sleep(1 * time.Second) // Back off on error
				continue
			}

			if len(result) != 2 {
				logging.Error("unexpected brpop result length",
					zap.Int("worker_id", workerID),
					zap.Int("length", len(result)),
				)
				continue
			}

			queueKey := result[0]
			data := result[1]

			var redisMsg RedisMessage
			if err := json.Unmarshal([]byte(data), &redisMsg); err != nil {
				logging.Error("failed to unmarshal redis message",
					zap.Int("worker_id", workerID),
					zap.String("queue", queueKey),
					zap.Error(err),
				)
				continue
			}

			// Process the message with retry logic
			q.processMessage(ctx, workerID, &redisMsg)
		}
	}
}

// processMessage sends an email with retry logic
func (q *RedisQueue) processMessage(ctx context.Context, workerID int, redisMsg *RedisMessage) {
	msg := redisMsg.Message
	maxRetries := q.cfg.RetryAttempts
	if maxRetries <= 0 {
		maxRetries = 3
	}
	baseDelay := time.Duration(q.cfg.RetryDelay) * time.Second
	if baseDelay <= 0 {
		baseDelay = 5 * time.Second
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: baseDelay * 2^(attempt-1), max 5 minutes
			delay := baseDelay * time.Duration(1<<uint(attempt-1))
			maxDelay := 5 * time.Minute
			if delay > maxDelay {
				delay = maxDelay
			}

			logging.Info("retrying email send",
				zap.Int("worker_id", workerID),
				zap.Int("attempt", attempt+1),
				zap.Int("max_retries", maxRetries),
				zap.Duration("delay", delay),
				zap.Strings("to", msg.To),
			)

			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
		}

		// Send the email
		start := time.Now()
		err := q.sender.Send(ctx, msg)
		duration := time.Since(start).Seconds()

		// Update metrics
		if attempt > 0 {
			EmailRetries.WithLabelValues(priorityString(msg.Priority)).Observe(float64(attempt))
		}

		if err == nil {
			// Success
			EmailsSentTotal.WithLabelValues("success", priorityString(msg.Priority)).Inc()
			EmailSendDuration.WithLabelValues("success").Observe(duration)

			logging.Info("email sent successfully from redis queue",
				zap.Int("worker_id", workerID),
				zap.Strings("to", msg.To),
				zap.String("subject", msg.Subject),
				zap.String("priority", priorityString(msg.Priority)),
				zap.Int("attempt", attempt+1),
			)
			return
		}

		// Log error
		EmailsSentTotal.WithLabelValues("error", priorityString(msg.Priority)).Inc()
		EmailSendDuration.WithLabelValues("error").Observe(duration)

		logging.Error("failed to send email from redis queue",
			zap.Int("worker_id", workerID),
			zap.Strings("to", msg.To),
			zap.String("subject", msg.Subject),
			zap.Int("attempt", attempt+1),
			zap.Int("max_retries", maxRetries),
			zap.Error(err),
		)

		// Update redis message with error
		redisMsg.Attempts = attempt + 1
		redisMsg.LastError = err.Error()

		// If this was the last attempt, move to DLQ
		if attempt == maxRetries-1 {
			q.moveToDLQ(context.Background(), redisMsg)
			return
		}
	}
}

// moveToDLQ moves a failed message to the dead letter queue
func (q *RedisQueue) moveToDLQ(ctx context.Context, redisMsg *RedisMessage) {
	data, err := json.Marshal(redisMsg)
	if err != nil {
		logging.Error("failed to marshal message for DLQ",
			zap.Error(err),
		)
		return
	}

	// Add to DLQ with score = current timestamp for sorting
	score := float64(time.Now().Unix())
	if err := q.rdb.ZAdd(ctx, queueKeyDLQ, redis.Z{
		Score:  score,
		Member: data,
	}).Err(); err != nil {
		logging.Error("failed to add message to DLQ",
			zap.Error(err),
		)
		return
	}

	EmailDLQSize.Inc()

	logging.Warn("message moved to dead letter queue",
		zap.Strings("to", redisMsg.Message.To),
		zap.String("subject", redisMsg.Message.Subject),
		zap.Int("attempts", redisMsg.Attempts),
		zap.String("last_error", redisMsg.LastError),
	)
}

// getQueueKey returns the Redis key for the given priority
func (q *RedisQueue) getQueueKey(priority Priority) string {
	switch priority {
	case PriorityCritical:
		return queueKeyCritical
	case PriorityHigh:
		return queueKeyHigh
	case PriorityNormal:
		return queueKeyNormal
	case PriorityLow:
		return queueKeyLow
	default:
		return queueKeyNormal
	}
}

// updateQueueMetrics updates Prometheus metrics for queue sizes
func (q *RedisQueue) updateQueueMetrics(ctx context.Context) {
	queues := []string{queueKeyCritical, queueKeyHigh, queueKeyNormal, queueKeyLow}
	total := 0
	for _, queue := range queues {
		size, _ := q.rdb.LLen(ctx, queue).Result()
		total += int(size)
	}
	EmailQueueSize.Set(float64(total))

	// Update DLQ size
	dlqSize, _ := q.rdb.ZCard(ctx, queueKeyDLQ).Result()
	EmailDLQSize.Set(float64(dlqSize))
}

// metricsUpdater periodically updates queue metrics
func (q *RedisQueue) metricsUpdater(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-q.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			q.updateQueueMetrics(ctx)
		}
	}
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

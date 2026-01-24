package email

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"paigram/internal/config"
	"paigram/internal/logging"
)

// MemoryQueue implements an in-memory email queue
type MemoryQueue struct {
	sender  Sender
	cfg     config.EmailConfig
	queue   chan *Message
	stopCh  chan struct{}
	wg      sync.WaitGroup
	started bool
	mu      sync.Mutex
}

// NewMemoryQueue creates a new in-memory queue
func NewMemoryQueue(sender Sender, cfg config.EmailConfig) *MemoryQueue {
	return &MemoryQueue{
		sender: sender,
		cfg:    cfg,
		queue:  make(chan *Message, 1000),
		stopCh: make(chan struct{}),
	}
}

// Enqueue adds a message to the queue
func (q *MemoryQueue) Enqueue(ctx context.Context, msg *Message) error {
	select {
	case q.queue <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fmt.Errorf("queue is full")
	}
}

// Start starts the queue processor
func (q *MemoryQueue) Start(ctx context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.started {
		return fmt.Errorf("queue already started")
	}

	q.started = true
	q.wg.Add(1)

	go q.process(ctx)

	logging.Info("email queue started")
	return nil
}

// Stop stops the queue processor
func (q *MemoryQueue) Stop() error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if !q.started {
		return nil
	}

	close(q.stopCh)
	q.wg.Wait()
	q.started = false

	logging.Info("email queue stopped")
	return nil
}

// process processes messages from the queue
func (q *MemoryQueue) process(ctx context.Context) {
	defer q.wg.Done()

	for {
		select {
		case <-q.stopCh:
			return
		case <-ctx.Done():
			return
		case msg := <-q.queue:
			q.sendWithRetry(ctx, msg)
		}
	}
}

// sendWithRetry sends a message with retry logic
func (q *MemoryQueue) sendWithRetry(ctx context.Context, msg *Message) {
	var lastErr error

	for attempt := 0; attempt <= q.cfg.RetryAttempts; attempt++ {
		if attempt > 0 {
			delay := time.Duration(q.cfg.RetryDelay) * time.Second
			logging.Info("retrying email send",
				zap.Int("attempt", attempt),
				zap.Duration("delay", delay),
			)
			time.Sleep(delay)
		}

		err := q.sender.Send(ctx, msg)
		if err == nil {
			logging.Info("email sent successfully",
				zap.Strings("to", msg.To),
				zap.String("subject", msg.Subject),
			)
			return
		}

		lastErr = err
		logging.Error("failed to send email",
			zap.Error(err),
			zap.Int("attempt", attempt+1),
			zap.Strings("to", msg.To),
		)
	}

	logging.Error("email send failed after all retries",
		zap.Error(lastErr),
		zap.Strings("to", msg.To),
		zap.String("subject", msg.Subject),
	)
}

// NoopQueue is a no-op implementation
type NoopQueue struct{}

// Enqueue does nothing
func (n *NoopQueue) Enqueue(ctx context.Context, msg *Message) error {
	return nil
}

// Start does nothing
func (n *NoopQueue) Start(ctx context.Context) error {
	return nil
}

// Stop does nothing
func (n *NoopQueue) Stop() error {
	return nil
}

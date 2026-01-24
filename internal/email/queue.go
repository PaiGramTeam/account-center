package email

import (
	"container/heap"
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"paigram/internal/config"
	"paigram/internal/logging"
)

// priorityMessage wraps a message with priority and timestamp
type priorityMessage struct {
	msg       *Message
	timestamp time.Time
	index     int // heap index
}

// priorityQueue implements heap.Interface for priority queue
type priorityQueue []*priorityMessage

func (pq priorityQueue) Len() int { return len(pq) }

func (pq priorityQueue) Less(i, j int) bool {
	// Higher priority comes first
	if pq[i].msg.Priority != pq[j].msg.Priority {
		return pq[i].msg.Priority > pq[j].msg.Priority
	}
	// Same priority, older messages first
	return pq[i].timestamp.Before(pq[j].timestamp)
}

func (pq priorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *priorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*priorityMessage)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *priorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*pq = old[0 : n-1]
	return item
}

// MemoryQueue implements an in-memory email queue with priority support
type MemoryQueue struct {
	sender   Sender
	cfg      config.EmailConfig
	queue    priorityQueue
	queueMu  sync.Mutex
	notifyCh chan struct{}
	stopCh   chan struct{}
	wg       sync.WaitGroup
	started  bool
	mu       sync.Mutex
}

// NewMemoryQueue creates a new in-memory queue
func NewMemoryQueue(sender Sender, cfg config.EmailConfig) *MemoryQueue {
	queueSize := cfg.QueueSize
	if queueSize <= 0 {
		queueSize = 1000 // Default queue size
	}

	mq := &MemoryQueue{
		sender:   sender,
		cfg:      cfg,
		queue:    make(priorityQueue, 0, queueSize),
		notifyCh: make(chan struct{}, 1),
		stopCh:   make(chan struct{}),
	}
	heap.Init(&mq.queue)
	return mq
}

// Enqueue adds a message to the queue
func (q *MemoryQueue) Enqueue(ctx context.Context, msg *Message) error {
	q.queueMu.Lock()
	defer q.queueMu.Unlock()

	// Check queue capacity
	queueSize := q.cfg.QueueSize
	if queueSize <= 0 {
		queueSize = 1000
	}

	if len(q.queue) >= queueSize {
		return fmt.Errorf("queue is full (capacity: %d)", queueSize)
	}

	// Add to priority queue
	pm := &priorityMessage{
		msg:       msg,
		timestamp: time.Now(),
	}
	heap.Push(&q.queue, pm)

	// Update queue size metric
	EmailQueueSize.Set(float64(len(q.queue)))

	// Notify worker
	select {
	case q.notifyCh <- struct{}{}:
	default:
	}

	return nil
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
		case <-q.notifyCh:
			q.processNext(ctx)
		}
	}
}

// processNext processes the next message in the queue
func (q *MemoryQueue) processNext(ctx context.Context) {
	q.queueMu.Lock()
	if len(q.queue) == 0 {
		q.queueMu.Unlock()
		return
	}

	pm := heap.Pop(&q.queue).(*priorityMessage)
	EmailQueueSize.Set(float64(len(q.queue)))
	q.queueMu.Unlock()

	// Send with retry
	q.sendWithRetry(ctx, pm.msg)

	// Check if there are more messages
	q.queueMu.Lock()
	hasMore := len(q.queue) > 0
	q.queueMu.Unlock()

	if hasMore {
		select {
		case q.notifyCh <- struct{}{}:
		default:
		}
	}
}

// sendWithRetry sends a message with exponential backoff retry logic
func (q *MemoryQueue) sendWithRetry(ctx context.Context, msg *Message) {
	var lastErr error
	maxRetries := q.cfg.RetryAttempts
	if maxRetries <= 0 {
		maxRetries = 3
	}

	baseDelay := time.Duration(q.cfg.RetryDelay) * time.Second
	if baseDelay <= 0 {
		baseDelay = 5 * time.Second
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: baseDelay * 2^(attempt-1)
			delay := baseDelay * time.Duration(1<<uint(attempt-1))
			// Cap at 5 minutes
			if delay > 5*time.Minute {
				delay = 5 * time.Minute
			}

			logging.Info("retrying email send",
				zap.Int("attempt", attempt),
				zap.Duration("delay", delay),
				zap.String("priority", priorityString(msg.Priority)),
			)

			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
		}

		err := q.sender.Send(ctx, msg)
		if err == nil {
			// Record successful retry count
			EmailRetries.WithLabelValues(priorityString(msg.Priority)).Observe(float64(attempt))

			logging.Info("email sent successfully",
				zap.Strings("to", msg.To),
				zap.String("subject", msg.Subject),
				zap.String("priority", priorityString(msg.Priority)),
				zap.Int("attempt", attempt+1),
			)
			return
		}

		lastErr = err
		logging.Error("failed to send email",
			zap.Error(err),
			zap.Int("attempt", attempt+1),
			zap.Strings("to", msg.To),
			zap.String("priority", priorityString(msg.Priority)),
		)
	}

	// Record failed retry count
	EmailRetries.WithLabelValues(priorityString(msg.Priority)).Observe(float64(maxRetries + 1))

	logging.Error("email send failed after all retries",
		zap.Error(lastErr),
		zap.Strings("to", msg.To),
		zap.String("subject", msg.Subject),
		zap.String("priority", priorityString(msg.Priority)),
		zap.Int("max_retries", maxRetries),
	)
}

// priorityString returns string representation of priority
func priorityString(p Priority) string {
	switch p {
	case PriorityCritical:
		return "critical"
	case PriorityHigh:
		return "high"
	case PriorityNormal:
		return "normal"
	case PriorityLow:
		return "low"
	default:
		return "unknown"
	}
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

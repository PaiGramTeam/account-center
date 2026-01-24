package email

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter defines the interface for rate limiting
type RateLimiter interface {
	Allow(key string) bool
	Wait(ctx context.Context, key string) error
}

// TokenBucketLimiter implements rate limiting using token bucket algorithm
type TokenBucketLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
	cleanup  time.Duration
}

// NewTokenBucketLimiter creates a new token bucket rate limiter
// ratePerSecond: number of emails allowed per second per recipient
// burst: maximum burst size
func NewTokenBucketLimiter(ratePerSecond float64, burst int) *TokenBucketLimiter {
	limiter := &TokenBucketLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     rate.Limit(ratePerSecond),
		burst:    burst,
		cleanup:  5 * time.Minute,
	}

	// Start cleanup goroutine
	go limiter.cleanupRoutine()

	return limiter
}

// Allow checks if the request is allowed
func (l *TokenBucketLimiter) Allow(key string) bool {
	limiter := l.getLimiter(key)
	return limiter.Allow()
}

// Wait waits until the request can proceed or context is cancelled
func (l *TokenBucketLimiter) Wait(ctx context.Context, key string) error {
	limiter := l.getLimiter(key)
	return limiter.Wait(ctx)
}

// getLimiter gets or creates a limiter for the key
func (l *TokenBucketLimiter) getLimiter(key string) *rate.Limiter {
	l.mu.RLock()
	limiter, exists := l.limiters[key]
	l.mu.RUnlock()

	if exists {
		return limiter
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Double-check after acquiring write lock
	limiter, exists = l.limiters[key]
	if exists {
		return limiter
	}

	limiter = rate.NewLimiter(l.rate, l.burst)
	l.limiters[key] = limiter
	return limiter
}

// cleanupRoutine periodically removes inactive limiters
func (l *TokenBucketLimiter) cleanupRoutine() {
	ticker := time.NewTicker(l.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		l.mu.Lock()
		// In a real implementation, you would track last access time
		// For now, we just keep all limiters
		l.mu.Unlock()
	}
}

// NoopRateLimiter is a no-op implementation that allows all requests
type NoopRateLimiter struct{}

// Allow always returns true
func (n *NoopRateLimiter) Allow(key string) bool {
	return true
}

// Wait does nothing
func (n *NoopRateLimiter) Wait(ctx context.Context, key string) error {
	return nil
}

// MultiKeyLimiter limits based on multiple keys (e.g., per-user and per-IP)
type MultiKeyLimiter struct {
	limiters []RateLimiter
}

// NewMultiKeyLimiter creates a new multi-key rate limiter
func NewMultiKeyLimiter(limiters []RateLimiter) *MultiKeyLimiter {
	return &MultiKeyLimiter{
		limiters: limiters,
	}
}

// Allow checks if all limiters allow the request
func (m *MultiKeyLimiter) Allow(keys ...string) bool {
	for i, limiter := range m.limiters {
		if i >= len(keys) {
			break
		}
		if !limiter.Allow(keys[i]) {
			return false
		}
	}
	return true
}

// Wait waits on all limiters
func (m *MultiKeyLimiter) Wait(ctx context.Context, keys ...string) error {
	for i, limiter := range m.limiters {
		if i >= len(keys) {
			break
		}
		if err := limiter.Wait(ctx, keys[i]); err != nil {
			return fmt.Errorf("wait on limiter %d: %w", i, err)
		}
	}
	return nil
}

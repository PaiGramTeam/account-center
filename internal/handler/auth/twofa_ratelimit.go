package auth

import (
	"sync"
	"time"
)

// twoFAFailRecord tracks failed 2FA attempts for a user
type twoFAFailRecord struct {
	count      int
	firstFail  time.Time
	lockedUtil time.Time
}

// memory2FARateLimiter provides in-memory fallback for 2FA rate limiting
// when Redis is unavailable. This is NOT suitable for multi-instance deployments
// but provides critical security protection when Redis fails.
type memory2FARateLimiter struct {
	mu      sync.RWMutex
	records map[uint64]*twoFAFailRecord
	// Cleanup interval
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
}

// newMemory2FARateLimiter creates a new in-memory 2FA rate limiter
func newMemory2FARateLimiter() *memory2FARateLimiter {
	limiter := &memory2FARateLimiter{
		records:       make(map[uint64]*twoFAFailRecord),
		cleanupTicker: time.NewTicker(5 * time.Minute),
		stopCleanup:   make(chan struct{}),
	}

	// Start cleanup goroutine
	go limiter.cleanup()

	return limiter
}

// cleanup removes expired records periodically
func (m *memory2FARateLimiter) cleanup() {
	for {
		select {
		case <-m.cleanupTicker.C:
			m.mu.Lock()
			now := time.Now()
			for userID, record := range m.records {
				// Remove if lock has expired
				if !record.lockedUtil.IsZero() && now.After(record.lockedUtil) {
					delete(m.records, userID)
				}
			}
			m.mu.Unlock()
		case <-m.stopCleanup:
			m.cleanupTicker.Stop()
			return
		}
	}
}

// isLocked checks if a user is locked out
func (m *memory2FARateLimiter) isLocked(userID uint64) (bool, time.Duration) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	record, exists := m.records[userID]
	if !exists {
		return false, 0
	}

	now := time.Now()

	// Check if lock has expired
	if !record.lockedUtil.IsZero() {
		if now.After(record.lockedUtil) {
			return false, 0
		}
		return true, record.lockedUtil.Sub(now)
	}

	return false, 0
}

// trackFailure increments failure counter
func (m *memory2FARateLimiter) trackFailure(userID uint64) int {
	const lockThreshold = 5
	const lockDuration = 15 * time.Minute

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	record, exists := m.records[userID]

	if !exists {
		record = &twoFAFailRecord{
			count:     1,
			firstFail: now,
		}
		m.records[userID] = record
		return 1
	}

	// Increment counter
	record.count++

	// Lock if threshold reached
	if record.count >= lockThreshold {
		record.lockedUtil = now.Add(lockDuration)
	}

	return record.count
}

// clearFailures removes failure records for a user
func (m *memory2FARateLimiter) clearFailures(userID uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, userID)
}

// stop halts the cleanup goroutine
func (m *memory2FARateLimiter) stop() {
	close(m.stopCleanup)
}

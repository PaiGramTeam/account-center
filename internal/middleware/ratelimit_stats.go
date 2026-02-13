package middleware

import (
	"sync"
	"time"
)

// RateLimitStats tracks rate limiting statistics for monitoring
type RateLimitStats struct {
	mu               sync.RWMutex
	totalBlocked     int64
	blockedByKey     map[string]int64
	lastBlockedByKey map[string]time.Time
	suspiciousKeys   map[string]int64 // Keys that hit rate limit frequently
	startTime        time.Time
}

var globalRateLimitStats = &RateLimitStats{
	blockedByKey:     make(map[string]int64),
	lastBlockedByKey: make(map[string]time.Time),
	suspiciousKeys:   make(map[string]int64),
	startTime:        time.Now(),
}

// recordBlock records a rate limit block event
func (s *RateLimitStats) recordBlock(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.totalBlocked++
	s.blockedByKey[key]++
	s.lastBlockedByKey[key] = time.Now()

	// Mark as suspicious if blocked more than 10 times
	if s.blockedByKey[key] > 10 {
		s.suspiciousKeys[key] = s.blockedByKey[key]
	}
}

// GetStats returns current rate limiting statistics
func (s *RateLimitStats) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	uptime := time.Since(s.startTime)

	// Find top offenders
	topOffenders := make([]map[string]interface{}, 0)
	for key, count := range s.suspiciousKeys {
		if count >= 10 { // Only include if blocked 10+ times
			topOffenders = append(topOffenders, map[string]interface{}{
				"key":          key,
				"block_count":  count,
				"last_blocked": s.lastBlockedByKey[key].Format(time.RFC3339),
			})
		}
	}

	return map[string]interface{}{
		"total_blocked":     s.totalBlocked,
		"unique_keys":       len(s.blockedByKey),
		"suspicious_keys":   len(s.suspiciousKeys),
		"top_offenders":     topOffenders,
		"uptime_seconds":    uptime.Seconds(),
		"blocks_per_minute": float64(s.totalBlocked) / uptime.Minutes(),
	}
}

// Reset clears all statistics
func (s *RateLimitStats) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.totalBlocked = 0
	s.blockedByKey = make(map[string]int64)
	s.lastBlockedByKey = make(map[string]time.Time)
	s.suspiciousKeys = make(map[string]int64)
	s.startTime = time.Now()
}

// GetRateLimitStats returns the global rate limiting statistics
func GetRateLimitStats() map[string]interface{} {
	return globalRateLimitStats.GetStats()
}

// ResetRateLimitStats resets the global rate limiting statistics
func ResetRateLimitStats() {
	globalRateLimitStats.Reset()
}

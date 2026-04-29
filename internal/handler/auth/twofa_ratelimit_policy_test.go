package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"paigram/internal/config"
	"paigram/internal/model"
	"paigram/internal/sessioncache"
)

// failingSessionCache wraps a noop session cache and forces IncrementCounter
// to return an error to simulate Redis being unavailable. Only the methods
// touched by the 2FA rate-limit code paths need to differ from the noop
// store; everything else delegates.
type failingSessionCache struct {
	*sessioncache.NoopStore
	err error
}

func (f *failingSessionCache) IncrementCounter(_ context.Context, _ string, _ time.Duration) (int64, error) {
	return 0, f.err
}

func (f *failingSessionCache) GetTTL(_ context.Context, _ string) (time.Duration, error) {
	return 0, f.err
}

func (f *failingSessionCache) Delete(_ context.Context, _ string) error {
	return f.err
}

// Test2FALock_FailsClosedWhenRedisDownAndPolicyRequiresRedis verifies
// V22: when the operator-configured policy requires Redis (the default)
// and Redis returns errors, is2FALocked must lock the account rather
// than silently fall back to a per-instance in-memory counter (which
// gets multiplied by N instances under load).
func Test2FALock_FailsClosedWhenRedisDownAndPolicyRequiresRedis(t *testing.T) {
	failing := &failingSessionCache{
		NoopStore: sessioncache.NewNoopStore(),
		err:       errors.New("redis: connection refused"),
	}

	h := &Handler{
		sessionCache:     failing,
		memory2FALimiter: newMemory2FARateLimiter(),
		securityCfg: config.SecurityConfig{
			RequireRedisFor2FA: true,
			TwoFAFailClosedTTL: 90 * time.Second,
		},
	}

	locked, ttl := h.is2FALocked(context.Background(), 4242)
	if !locked {
		t.Fatalf("is2FALocked must fail closed (locked=true) when Redis is down and policy requires Redis")
	}
	if ttl <= 0 {
		t.Fatalf("is2FALocked must return a positive TTL on fail-closed; got %v", ttl)
	}
	if ttl != 90*time.Second {
		t.Fatalf("expected configured TwoFAFailClosedTTL to flow through; got %v", ttl)
	}

	// track2FAFailure must surface the Redis error rather than silently
	// recording in the per-instance memory limiter (and therefore
	// undermining the cluster-wide threshold).
	if err := h.track2FAFailure(context.Background(), 4242); err == nil {
		t.Fatalf("track2FAFailure must return an error when Redis is down and policy requires Redis")
	}
}

// Test2FALock_FallsBackToMemoryWhenRedisDownAndPolicyAllows verifies the
// opt-out path. Local-dev or single-instance deployments may explicitly
// allow the in-memory fallback by setting RequireRedisFor2FA=false. Then
// is2FALocked must accumulate failures via the in-memory limiter and
// eventually lock — proving the fallback is *real* rate limiting, not a
// no-op that pretends to record but never trips.
func Test2FALock_FallsBackToMemoryWhenRedisDownAndPolicyAllows(t *testing.T) {
	failing := &failingSessionCache{
		NoopStore: sessioncache.NewNoopStore(),
		err:       errors.New("redis: connection refused"),
	}

	const userID uint64 = 9999

	h := &Handler{
		sessionCache:     failing,
		memory2FALimiter: newMemory2FARateLimiter(),
		securityCfg: config.SecurityConfig{
			RequireRedisFor2FA: false,
		},
	}

	// Initial: no failures recorded yet — memory limiter must report unlocked.
	locked, _ := h.is2FALocked(context.Background(), userID)
	if locked {
		t.Fatalf("is2FALocked must NOT fail closed when policy allows in-memory fallback (initial lookup)")
	}

	// memory2FARateLimiter.trackFailure locks at >= 5 failures with a
	// 15-minute window (see internal/handler/auth/twofa_ratelimit.go).
	// Drive that many failures and assert the lock triggers — this is
	// the contract the test must verify, not just that the calls
	// returned nil.
	const memoryLimiterThreshold = 5
	for i := 0; i < memoryLimiterThreshold; i++ {
		if err := h.track2FAFailure(context.Background(), userID); err != nil {
			t.Fatalf("track2FAFailure must succeed via memory limiter when policy allows fallback (iteration %d): %v", i, err)
		}
	}

	locked, ttl := h.is2FALocked(context.Background(), userID)
	if !locked {
		t.Fatalf("after %d in-memory failures the user must be locked; got locked=false", memoryLimiterThreshold)
	}
	if ttl <= 0 {
		t.Fatalf("memory-limiter lock must report a positive remaining TTL; got %v", ttl)
	}
	// The memory limiter uses a 15-minute lock duration. Allow a wide
	// window because we cannot freeze time here; just assert it's in a
	// sane neighbourhood.
	const memoryLimiterLock = 15 * time.Minute
	if ttl > memoryLimiterLock+time.Second {
		t.Fatalf("memory-limiter TTL %v exceeds the documented %v lock window", ttl, memoryLimiterLock)
	}
	if ttl < memoryLimiterLock-time.Minute {
		t.Fatalf("memory-limiter TTL %v is suspiciously short compared to the documented %v lock window", ttl, memoryLimiterLock)
	}
}

// Compile-time assertion: model used in helper imports above.
var _ = model.UserStatusActive

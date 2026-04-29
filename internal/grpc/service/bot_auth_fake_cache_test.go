package service_test

import (
	"context"
	"sync"
	"time"

	"paigram/internal/cache"
)

// inMemoryBotTokenCache is a test-only fake that implements
// cache.BotTokenCacheStore against in-process maps. It exists so we can assert
// that BotAuthService correctly invalidates cache entries on token rotation
// and reuse detection without standing up a real Redis (or pulling in
// miniredis as a new dependency for this fix).
//
// Concurrency: every operation takes a single mutex. That's overkill for a
// test fake but keeps the goroutined fire-and-forget calls in the service
// layer race-free under -race.
type inMemoryBotTokenCache struct {
	mu      sync.Mutex
	entries map[string]*cache.BotTokenCacheData
	revoked map[string]time.Time // hash -> expires_at
}

func newInMemoryBotTokenCache() *inMemoryBotTokenCache {
	return &inMemoryBotTokenCache{
		entries: make(map[string]*cache.BotTokenCacheData),
		revoked: make(map[string]time.Time),
	}
}

func (c *inMemoryBotTokenCache) Get(_ context.Context, tokenHash string) (*cache.BotTokenCacheData, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if data, ok := c.entries[tokenHash]; ok {
		// Return a shallow copy so callers can't mutate our stored entry.
		copy := *data
		return &copy, nil
	}
	return nil, errCacheMiss
}

func (c *inMemoryBotTokenCache) Set(_ context.Context, tokenHash string, data *cache.BotTokenCacheData) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	stored := *data
	c.entries[tokenHash] = &stored
	return nil
}

func (c *inMemoryBotTokenCache) UpdateRateLimit(_ context.Context, tokenHash string, requestCount int, lastRequest time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.entries[tokenHash]; ok {
		existing.RequestCount = requestCount
		existing.LastRequest = &lastRequest
	}
	return nil
}

func (c *inMemoryBotTokenCache) Delete(_ context.Context, tokenHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, tokenHash)
	return nil
}

func (c *inMemoryBotTokenCache) IsRevoked(_ context.Context, tokenHash string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.revoked[tokenHash]
	return ok, nil
}

func (c *inMemoryBotTokenCache) MarkRevoked(_ context.Context, tokenHash string, expiresAt time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revoked[tokenHash] = expiresAt
	return nil
}

// hasEntry reports whether a positive cache entry currently exists for
// tokenHash. Tests use this to assert that rotation/reuse paths invalidated
// the cache as a side effect.
func (c *inMemoryBotTokenCache) hasEntry(tokenHash string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.entries[tokenHash]
	return ok
}

// isRevoked reports whether tokenHash was tombstoned in the revocation set.
func (c *inMemoryBotTokenCache) isRevoked(tokenHash string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.revoked[tokenHash]
	return ok
}

// errCacheMiss mirrors what go-redis returns on a missing key (redis.Nil), so
// the production cache-hit code path treats our fake's misses identically.
var errCacheMiss = cacheMissError{}

type cacheMissError struct{}

func (cacheMissError) Error() string { return "cache: miss" }

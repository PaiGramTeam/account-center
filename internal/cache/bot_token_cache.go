package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// BotTokenCache provides Redis caching for bot token validation
type BotTokenCache struct {
	client *redis.Client
	prefix string
}

// NewBotTokenCache creates a new bot token cache
func NewBotTokenCache(client *redis.Client, prefix string) *BotTokenCache {
	if prefix == "" {
		prefix = "bot_token:"
	}
	return &BotTokenCache{
		client: client,
		prefix: prefix,
	}
}

// BotTokenCacheData represents cached token validation data
type BotTokenCacheData struct {
	Valid               bool       `json:"valid"`
	BotID               string     `json:"bot_id"`
	BotName             string     `json:"bot_name"`
	BotStatus           string     `json:"bot_status"`
	Scopes              []string   `json:"scopes"`
	ExpiresAt           time.Time  `json:"expires_at"`
	RateLimitEnabled    bool       `json:"rate_limit_enabled"`
	RateLimitTimeWindow *int64     `json:"rate_limit_time_window,omitempty"`
	RateLimitMax        *int       `json:"rate_limit_max,omitempty"`
	RequestCount        int        `json:"request_count"`
	LastRequest         *time.Time `json:"last_request,omitempty"`
}

// Get retrieves cached token validation data
func (c *BotTokenCache) Get(ctx context.Context, tokenHash string) (*BotTokenCacheData, error) {
	if c.client == nil {
		return nil, fmt.Errorf("redis client not available")
	}

	key := c.prefix + tokenHash
	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	var cacheData BotTokenCacheData
	if err := json.Unmarshal([]byte(data), &cacheData); err != nil {
		return nil, fmt.Errorf("unmarshal cache data: %w", err)
	}

	return &cacheData, nil
}

// Set caches token validation data with TTL based on token expiry
func (c *BotTokenCache) Set(ctx context.Context, tokenHash string, data *BotTokenCacheData) error {
	if c.client == nil {
		return fmt.Errorf("redis client not available")
	}

	key := c.prefix + tokenHash
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal cache data: %w", err)
	}

	// Calculate TTL: use token expiry time, but cap at 1 hour for rate limit freshness
	ttl := time.Until(data.ExpiresAt)
	if ttl > time.Hour {
		ttl = time.Hour
	}
	if ttl <= 0 {
		// Don't cache expired tokens
		return nil
	}

	return c.client.Set(ctx, key, jsonData, ttl).Err()
}

// UpdateRateLimit updates only the rate limit counters in cache
func (c *BotTokenCache) UpdateRateLimit(ctx context.Context, tokenHash string, requestCount int, lastRequest time.Time) error {
	if c.client == nil {
		return fmt.Errorf("redis client not available")
	}

	// Get current cached data
	cacheData, err := c.Get(ctx, tokenHash)
	if err != nil {
		// Cache miss is not an error - will be updated on next full validation
		return nil
	}

	// Update rate limit fields
	cacheData.RequestCount = requestCount
	cacheData.LastRequest = &lastRequest

	// Re-cache with updated data
	return c.Set(ctx, tokenHash, cacheData)
}

// Delete removes cached token data (e.g., when token is revoked)
func (c *BotTokenCache) Delete(ctx context.Context, tokenHash string) error {
	if c.client == nil {
		return fmt.Errorf("redis client not available")
	}

	key := c.prefix + tokenHash
	return c.client.Del(ctx, key).Err()
}

// IsRevoked checks if a token hash is in the revocation list
func (c *BotTokenCache) IsRevoked(ctx context.Context, tokenHash string) (bool, error) {
	if c.client == nil {
		return false, fmt.Errorf("redis client not available")
	}

	key := c.prefix + "revoked:" + tokenHash
	exists, err := c.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}

	return exists > 0, nil
}

// MarkRevoked adds a token to the revocation list (TTL: 24 hours)
func (c *BotTokenCache) MarkRevoked(ctx context.Context, tokenHash string, expiresAt time.Time) error {
	if c.client == nil {
		return fmt.Errorf("redis client not available")
	}

	key := c.prefix + "revoked:" + tokenHash

	// TTL: until token would have expired anyway (max 24 hours)
	ttl := time.Until(expiresAt)
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	if ttl <= 0 {
		ttl = 1 * time.Hour // Minimum 1 hour
	}

	return c.client.Set(ctx, key, "1", ttl).Err()
}

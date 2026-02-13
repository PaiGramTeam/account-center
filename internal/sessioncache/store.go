package sessioncache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"paigram/internal/model"
)

// TokenType identifies the type of token being cached.
type TokenType string

const (
	// TokenTypeAccess marks an access token cache entry.
	TokenTypeAccess TokenType = "access"
	// TokenTypeRefresh marks a refresh token cache entry.
	TokenTypeRefresh TokenType = "refresh"
)

// Store declares the behaviour supported by all session caches.
type Store interface {
	SaveSession(ctx context.Context, session *model.UserSession) error
	RemoveTokens(ctx context.Context, accessToken, refreshToken string) error
	GetSessionID(ctx context.Context, tokenType TokenType, token string) (uint64, error)
	MarkRevoked(ctx context.Context, tokenType TokenType, token string, ttl time.Duration) error
	IsRevoked(ctx context.Context, tokenType TokenType, token string) (bool, error)

	// Counter operations for rate limiting
	IncrementCounter(ctx context.Context, key string, ttl time.Duration) (int64, error)
	GetTTL(ctx context.Context, key string) (time.Duration, error)
	Delete(ctx context.Context, key string) error
}

// RedisStore implements Store backed by Redis.
type RedisStore struct {
	client *redis.Client
	prefix string
}

// NewRedisStore constructs a Redis-backed session cache.
func NewRedisStore(client *redis.Client, prefix string) *RedisStore {
	return &RedisStore{client: client, prefix: prefix}
}

type tokenPayload struct {
	SessionID uint64 `json:"session_id"`
	UserID    uint64 `json:"user_id"`
}

func (s *RedisStore) SaveSession(ctx context.Context, session *model.UserSession) error {
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}

	payload := tokenPayload{
		SessionID: session.ID,
		UserID:    session.UserID,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	accessTTL := time.Until(session.AccessExpiry)
	if accessTTL <= 0 {
		accessTTL = time.Second
	}
	refreshTTL := time.Until(session.RefreshExpiry)
	if refreshTTL <= 0 {
		refreshTTL = time.Second
	}

	pipe := s.client.Pipeline()
	pipe.Set(ctx, s.tokenKey(TokenTypeAccess, session.AccessToken), data, accessTTL)
	pipe.Set(ctx, s.tokenKey(TokenTypeRefresh, session.RefreshToken), data, refreshTTL)
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("cache session tokens: %w", err)
	}
	return nil
}

func (s *RedisStore) RemoveTokens(ctx context.Context, accessToken, refreshToken string) error {
	keys := make([]string, 0, 2)
	if accessToken != "" {
		keys = append(keys, s.tokenKey(TokenTypeAccess, accessToken))
	}
	if refreshToken != "" {
		keys = append(keys, s.tokenKey(TokenTypeRefresh, refreshToken))
	}
	if len(keys) == 0 {
		return nil
	}
	if err := s.client.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("remove session tokens: %w", err)
	}
	return nil
}

func (s *RedisStore) GetSessionID(ctx context.Context, tokenType TokenType, token string) (uint64, error) {
	if token == "" {
		return 0, fmt.Errorf("token cannot be empty")
	}
	cmd := s.client.Get(ctx, s.tokenKey(tokenType, token))
	if err := cmd.Err(); err != nil {
		return 0, err
	}
	var payload tokenPayload
	if err := json.Unmarshal([]byte(cmd.Val()), &payload); err != nil {
		return 0, fmt.Errorf("unmarshal payload: %w", err)
	}
	return payload.SessionID, nil
}

func (s *RedisStore) MarkRevoked(ctx context.Context, tokenType TokenType, token string, ttl time.Duration) error {
	if token == "" {
		return nil
	}
	key := s.revokedKey(tokenType, token)
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if err := s.client.Set(ctx, key, "1", ttl).Err(); err != nil {
		return fmt.Errorf("mark revoked: %w", err)
	}
	return nil
}

func (s *RedisStore) IsRevoked(ctx context.Context, tokenType TokenType, token string) (bool, error) {
	if token == "" {
		return false, nil
	}
	key := s.revokedKey(tokenType, token)
	cmd := s.client.Exists(ctx, key)
	if err := cmd.Err(); err != nil {
		return false, err
	}
	return cmd.Val() > 0, nil
}

func (s *RedisStore) tokenKey(tokenType TokenType, token string) string {
	return fmt.Sprintf("%s:session:%s:%s", s.prefix, tokenType, token)
}

func (s *RedisStore) revokedKey(tokenType TokenType, token string) string {
	return fmt.Sprintf("%s:session:revoked:%s:%s", s.prefix, tokenType, token)
}

// IncrementCounter increments a counter and sets expiry if not exists
func (s *RedisStore) IncrementCounter(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	fullKey := fmt.Sprintf("%s:%s", s.prefix, key)

	// Increment the counter
	count, err := s.client.Incr(ctx, fullKey).Result()
	if err != nil {
		return 0, fmt.Errorf("increment counter: %w", err)
	}

	// Set expiry only if this is the first increment (count == 1)
	if count == 1 && ttl > 0 {
		if err := s.client.Expire(ctx, fullKey, ttl).Err(); err != nil {
			return count, fmt.Errorf("set expiry: %w", err)
		}
	}

	return count, nil
}

// GetTTL returns the remaining TTL for a key
func (s *RedisStore) GetTTL(ctx context.Context, key string) (time.Duration, error) {
	fullKey := fmt.Sprintf("%s:%s", s.prefix, key)
	ttl, err := s.client.TTL(ctx, fullKey).Result()
	if err != nil {
		return 0, fmt.Errorf("get TTL: %w", err)
	}
	return ttl, nil
}

// Delete removes a key from Redis
func (s *RedisStore) Delete(ctx context.Context, key string) error {
	fullKey := fmt.Sprintf("%s:%s", s.prefix, key)
	if err := s.client.Del(ctx, fullKey).Err(); err != nil {
		return fmt.Errorf("delete key: %w", err)
	}
	return nil
}

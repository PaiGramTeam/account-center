package sessioncache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	SaveSessionWithTokens(ctx context.Context, session *model.UserSession, accessToken, refreshToken string) error
	RemoveTokens(ctx context.Context, accessToken, refreshToken string) error
	GetSessionID(ctx context.Context, tokenType TokenType, token string) (uint64, error)
	GetSessionData(ctx context.Context, tokenType TokenType, token string) (*SessionData, error)
	MarkRevoked(ctx context.Context, tokenType TokenType, token string, ttl time.Duration) error
	IsRevoked(ctx context.Context, tokenType TokenType, token string) (bool, error)

	// Counter operations for rate limiting
	IncrementCounter(ctx context.Context, key string, ttl time.Duration) (int64, error)
	GetTTL(ctx context.Context, key string) (time.Duration, error)
	Delete(ctx context.Context, key string) error

	// Generic key-value operations
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Get(ctx context.Context, key string) ([]byte, error)
}

// SessionData holds cached session information for fast validation
type SessionData struct {
	SessionID     uint64
	UserID        uint64
	AccessExpiry  time.Time
	RefreshExpiry time.Time
	RevokedAt     *time.Time
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
	SessionID     uint64     `json:"session_id"`
	UserID        uint64     `json:"user_id"`
	AccessExpiry  time.Time  `json:"access_expiry"`
	RefreshExpiry time.Time  `json:"refresh_expiry"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

func (s *RedisStore) SaveSession(ctx context.Context, session *model.UserSession) error {
	// This method is deprecated, kept for backward compatibility
	// SaveSessionWithTokens should be used instead
	return fmt.Errorf("SaveSession is deprecated, use SaveSessionWithTokens")
}

// SaveSessionWithTokens stores session data in cache using the original (unhashed) tokens as keys
func (s *RedisStore) SaveSessionWithTokens(ctx context.Context, session *model.UserSession, accessToken, refreshToken string) error {
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}
	if accessToken == "" || refreshToken == "" {
		return fmt.Errorf("tokens cannot be empty")
	}

	var revokedAt *time.Time
	if session.RevokedAt.Valid {
		revokedAt = &session.RevokedAt.Time
	}

	payload := tokenPayload{
		SessionID:     session.ID,
		UserID:        session.UserID,
		AccessExpiry:  session.AccessExpiry,
		RefreshExpiry: session.RefreshExpiry,
		RevokedAt:     revokedAt,
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
	pipe.Set(ctx, s.tokenKey(TokenTypeAccess, accessToken), data, accessTTL)
	pipe.Set(ctx, s.tokenKey(TokenTypeRefresh, refreshToken), data, refreshTTL)
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

// GetSessionData retrieves full cached session data for fast validation
func (s *RedisStore) GetSessionData(ctx context.Context, tokenType TokenType, token string) (*SessionData, error) {
	if token == "" {
		return nil, fmt.Errorf("token cannot be empty")
	}
	cmd := s.client.Get(ctx, s.tokenKey(tokenType, token))
	if err := cmd.Err(); err != nil {
		return nil, err
	}
	var payload tokenPayload
	if err := json.Unmarshal([]byte(cmd.Val()), &payload); err != nil {
		return nil, fmt.Errorf("unmarshal payload: %w", err)
	}

	return &SessionData{
		SessionID:     payload.SessionID,
		UserID:        payload.UserID,
		AccessExpiry:  payload.AccessExpiry,
		RefreshExpiry: payload.RefreshExpiry,
		RevokedAt:     payload.RevokedAt,
	}, nil
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
	return fmt.Sprintf("%s:session:%s:%s", s.prefix, tokenType, hashTokenForKey(token))
}

func (s *RedisStore) revokedKey(tokenType TokenType, token string) string {
	return fmt.Sprintf("%s:session:revoked:%s:%s", s.prefix, tokenType, hashTokenForKey(token))
}

// hashTokenForKey returns the SHA-256 hex digest of token. The package uses
// it to derive Redis keys so that a Redis snapshot, MEMORY/KEYS leak, or
// slowlog entry never exposes raw access/refresh tokens. The transform is
// applied transparently inside the package; callers continue to pass the
// original token to the public API (V4 hardening).
//
// hashTokenForKey is a pure SHA-256 hex transform: it does NOT special-case
// the empty string. Public methods on RedisStore guard against empty tokens
// before reaching the key builders, so an empty input here is already a
// caller bug. We deliberately let it produce the well-known empty-input
// digest (e3b0c4...) rather than returning "" -- the latter would silently
// collide every empty-input bug onto the same Redis key shape (`prefix:session:access:`)
// and create a cache-poisoning failure mode that's indistinguishable from
// real traffic. Code-review feedback on commit 7e420e0.
func hashTokenForKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// RevokedSessionMarkerKey returns the generic cache key used to invalidate a session by ID.
func RevokedSessionMarkerKey(sessionID uint64) string {
	return fmt.Sprintf("session:revoked:session-id:%d", sessionID)
}

// RevokedSessionMarkerTTL keeps revoke markers alive for the remaining refresh lifetime.
func RevokedSessionMarkerTTL(session *model.UserSession) time.Duration {
	if session == nil {
		return 24 * time.Hour
	}

	ttl := time.Until(session.RefreshExpiry)
	if ttl <= 0 {
		return 24 * time.Hour
	}

	return ttl
}

// CurrentAccessTokenHashKey returns the cache key storing the current access-token hash for a session.
func CurrentAccessTokenHashKey(sessionID uint64) string {
	return fmt.Sprintf("session:current-access-hash:%d", sessionID)
}

// CurrentAccessTokenHashTTL keeps the current access-token marker aligned to refresh expiry.
func CurrentAccessTokenHashTTL(session *model.UserSession) time.Duration {
	return RevokedSessionMarkerTTL(session)
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

// Set stores a value with optional TTL
func (s *RedisStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	fullKey := fmt.Sprintf("%s:%s", s.prefix, key)
	if err := s.client.Set(ctx, fullKey, value, ttl).Err(); err != nil {
		return fmt.Errorf("set value: %w", err)
	}
	return nil
}

// Get retrieves a value by key
func (s *RedisStore) Get(ctx context.Context, key string) ([]byte, error) {
	fullKey := fmt.Sprintf("%s:%s", s.prefix, key)
	val, err := s.client.Get(ctx, fullKey).Bytes()
	if err != nil {
		return nil, err
	}
	return val, nil
}

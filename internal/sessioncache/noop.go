package sessioncache

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"

	"paigram/internal/model"
)

// NoopStore implements Store without performing any caching.
type NoopStore struct{}

// NewNoopStore returns a Store that does nothing.
func NewNoopStore() *NoopStore {
	return &NoopStore{}
}

func (*NoopStore) SaveSession(_ context.Context, _ *model.UserSession) error {
	return nil
}

func (*NoopStore) RemoveTokens(_ context.Context, _, _ string) error {
	return nil
}

func (*NoopStore) GetSessionID(_ context.Context, _ TokenType, _ string) (uint64, error) {
	return 0, redis.Nil
}

func (*NoopStore) MarkRevoked(_ context.Context, _ TokenType, _ string, _ time.Duration) error {
	return nil
}

func (*NoopStore) IsRevoked(_ context.Context, _ TokenType, _ string) (bool, error) {
	return false, nil
}

func (*NoopStore) IncrementCounter(_ context.Context, _ string, _ time.Duration) (int64, error) {
	return 0, nil
}

func (*NoopStore) GetTTL(_ context.Context, _ string) (time.Duration, error) {
	return 0, nil
}

func (*NoopStore) Delete(_ context.Context, _ string) error {
	return nil
}

func (*NoopStore) Set(_ context.Context, _ string, _ []byte, _ time.Duration) error {
	return nil
}

func (*NoopStore) Get(_ context.Context, _ string) ([]byte, error) {
	return nil, redis.Nil
}

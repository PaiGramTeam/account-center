package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"paigram/internal/config"
)

// NewRedisClient constructs a go-redis client using application configuration.
func NewRedisClient(cfg config.RedisConfig) (*redis.Client, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("redis is disabled")
	}

	opts := &redis.Options{
		Addr:         cfg.Addr,
		Username:     cfg.Username,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  time.Duration(cfg.DialTimeout) * time.Second,
		ReadTimeout:  time.Duration(cfg.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.WriteTimeout) * time.Second,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		MaxRetries:   cfg.MaxRetries,
	}

	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	return client, nil
}

// MustNewRedisClient returns a client or panics if initialization fails.
func MustNewRedisClient(cfg config.RedisConfig) *redis.Client {
	client, err := NewRedisClient(cfg)
	if err != nil {
		panic(err)
	}
	return client
}

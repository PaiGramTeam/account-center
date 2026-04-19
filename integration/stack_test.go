//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"

	initmigrate "paigram/initialize/migrate"
	"paigram/internal/casbin"
	"paigram/internal/config"
	"paigram/internal/crypto"
	"paigram/internal/email"
	"paigram/internal/middleware"
	"paigram/internal/model"
	"paigram/internal/router"
	"paigram/internal/sessioncache"
	"paigram/internal/testutil/integrationenv"
)

type integrationStack struct {
	Env         integrationenv.Env
	DatabaseCfg config.DatabaseConfig
	SQLDB       *sql.DB
	DB          *gorm.DB
	Redis       *redis.Client
	RedisPrefix string
	Email       *email.Service
	Router      http.Handler
	cleanup     []func()
}

func newIntegrationStack(t *testing.T) *integrationStack {
	return newIntegrationStackWithConfig(t, nil)
}

func newIntegrationStackWithConfig(t *testing.T, mutate func(*config.Config)) *integrationStack {
	t.Helper()
	require.NoError(t, crypto.SetEncryptionKey([]byte("0123456789abcdef0123456789abcdef")))

	env, err := integrationenv.Load(integrationenv.LoadOptions{})
	require.NoError(t, err)

	missing := env.MissingRequired()
	if len(missing) > 0 {
		t.Skipf("integration env not configured: missing %s", strings.Join(missing, ", "))
	}

	stack := &integrationStack{Env: env}

	dbName := env.UniqueDatabaseName(t.Name())
	stack.RedisPrefix = env.UniqueRedisPrefix(t.Name())
	t.Logf("integration stack resources: mysql_database=%s redis_prefix=%s", dbName, stack.RedisPrefix)

	rootDB := openMySQLRootDB(t, env)
	createDatabase(t, rootDB, dbName)
	stack.cleanup = append(stack.cleanup, func() {
		dropDatabase(t, rootDB, dbName)
		_ = rootDB.Close()
	})

	stack.DatabaseCfg = config.DatabaseConfig{
		Addr:          env.MySQLAddr,
		Username:      env.MySQLUsername,
		Password:      env.MySQLPassword,
		Dbname:        dbName,
		Config:        env.MySQLConfig,
		MigrationsDir: migrationsDir(env.RepoRoot),
		AutoMigrate:   false,
		AutoSeed:      false,
	}

	migrationDB := openMySQLDatabase(t, stack.DatabaseCfg)
	runMigrations(t, migrationDB, stack.DatabaseCfg)
	_ = migrationDB.Close()

	stack.SQLDB = openMySQLDatabase(t, stack.DatabaseCfg)
	stack.cleanup = append(stack.cleanup, func() {
		_ = stack.SQLDB.Close()
	})

	stack.DB, err = gorm.Open(gormmysql.Open(buildMySQLDSN(stack.DatabaseCfg)), &gorm.Config{})
	require.NoError(t, err)
	gormSQLDB, err := stack.DB.DB()
	require.NoError(t, err)
	stack.cleanup = append(stack.cleanup, func() {
		_ = gormSQLDB.Close()
	})

	stack.Redis = openRedis(t, env)
	cleanupRedisPrefix(t, stack.Redis, stack.RedisPrefix)
	stack.cleanup = append(stack.cleanup, func() {
		cleanupRedisPrefix(t, stack.Redis, stack.RedisPrefix)
		_ = stack.Redis.Close()
	})

	emailService, err := email.NewService(config.EmailConfig{Enabled: false})
	require.NoError(t, err)
	stack.Email = emailService
	stack.cleanup = append(stack.cleanup, func() {
		_ = stack.Email.Close()
	})

	sessionStore := sessioncache.NewRedisStore(stack.Redis, stack.RedisPrefix)
	rateLimitStore, err := middleware.NewRedisStore(stack.Redis, stack.RedisPrefix+":ratelimit")
	require.NoError(t, err)

	testCfg := newTestConfig(env, stack.RedisPrefix)
	if mutate != nil {
		mutate(testCfg)
	}

	stack.Router, err = router.New(testCfg, sessionStore, stack.DB, rateLimitStore, stack.Email)
	require.NoError(t, err)

	casbin.Reset()
	_, err = casbin.InitEnforcer(stack.DB)
	require.NoError(t, err, "Failed to initialize Casbin enforcer")

	t.Cleanup(func() {
		for i := len(stack.cleanup) - 1; i >= 0; i-- {
			stack.cleanup[i]()
		}
	})

	return stack
}

func newTestConfig(env integrationenv.Env, redisPrefix string) *config.Config {
	return &config.Config{
		App: config.AppConfig{
			Name:           "Paigram Integration Test",
			Mode:           "test",
			TrustedProxies: []string{"127.0.0.1"},
			IPv6Subnet:     64,
		},
		Auth: config.AuthConfig{
			AccessTokenTTLSeconds:         900,
			RefreshTokenTTLSeconds:        604800,
			EmailVerificationTTLSeconds:   86400,
			SessionUpdateAgeSeconds:       86400,
			SessionFreshAgeSeconds:        300,
			RequireEmailVerificationLogin: true,
			ServiceTicketTTLSeconds:       300,
			ServiceTicketIssuer:           "paigram-account-center",
			ServiceTicketSigningKey:       "0123456789abcdef0123456789abcdef",
		},
		Redis: config.RedisConfig{
			Enabled:  true,
			Addr:     env.RedisAddr,
			Password: env.RedisPassword,
			DB:       env.RedisDB,
			Prefix:   redisPrefix,
		},
		RateLimit: config.RateLimitConfig{
			Enabled: true,
			Auth: config.RateLimitAuthConfig{
				Login:        "10-M",
				Register:     "10-M",
				VerifyEmail:  "10-M",
				RefreshToken: "10-M",
				OAuth:        "10-M",
			},
			API: config.RateLimitAPIConfig{
				Authenticated:   "100-H",
				Unauthenticated: "100-H",
			},
		},
		Email: config.EmailConfig{Enabled: false},
		Security: config.SecurityConfig{
			SuspiciousLoginDetection:  false,
			SuspiciousLoginEmailAlert: false,
			BcryptCost:                10,
		},
	}
}

func openMySQLRootDB(t *testing.T, env integrationenv.Env) *sql.DB {
	t.Helper()

	db, err := sql.Open("mysql", env.RootMySQLDSN())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	require.NoError(t, db.PingContext(ctx))

	return db
}

func openMySQLDatabase(t *testing.T, cfg config.DatabaseConfig) *sql.DB {
	t.Helper()

	db, err := sql.Open("mysql", buildMySQLDSN(cfg))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	require.NoError(t, db.PingContext(ctx))

	return db
}

func createDatabase(t *testing.T, rootDB *sql.DB, dbName string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, err := rootDB.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", dbName))
	require.NoError(t, err)
}

func dropDatabase(t *testing.T, rootDB *sql.DB, dbName string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, err := rootDB.ExecContext(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", dbName))
	require.NoError(t, err)
}

func openRedis(t *testing.T, env integrationenv.Env) *redis.Client {
	t.Helper()

	client := redis.NewClient(&redis.Options{
		Addr:     env.RedisAddr,
		Password: env.RedisPassword,
		DB:       env.RedisDB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, client.Ping(ctx).Err())

	return client
}

func cleanupRedisPrefix(t *testing.T, client *redis.Client, prefix string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var cursor uint64
	pattern := prefix + "*"
	for {
		keys, nextCursor, err := client.Scan(ctx, cursor, pattern, 100).Result()
		require.NoError(t, err)
		if len(keys) > 0 {
			require.NoError(t, client.Del(ctx, keys...).Err())
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
}

func runMigrations(t *testing.T, sqlDB *sql.DB, cfg config.DatabaseConfig) {
	t.Helper()
	require.NoError(t, initmigrate.Run(sqlDB, cfg))
}

func migrationsDir(repoRoot string) string {
	return filepath.Join(repoRoot, "initialize", "migrate", "sql")
}

func requireTableExists(t *testing.T, db *sql.DB, schema, table string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var count int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM information_schema.tables
		WHERE table_schema = ? AND table_name = ?
	`, schema, table).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count, "expected table %s to exist", table)
}

func hashTokenForTest(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func buildMySQLDSN(cfg config.DatabaseConfig) string {
	query := trimQueryPrefix(cfg.Config)
	if query == "" {
		return fmt.Sprintf("%s:%s@tcp(%s)/%s", cfg.Username, cfg.Password, cfg.Addr, cfg.Dbname)
	}
	return fmt.Sprintf("%s:%s@tcp(%s)/%s?%s", cfg.Username, cfg.Password, cfg.Addr, cfg.Dbname, query)
}

func trimQueryPrefix(query string) string {
	return strings.TrimPrefix(strings.TrimSpace(query), "?")
}

func requireSessionForRefreshToken(t *testing.T, db *gorm.DB, refreshToken string) model.UserSession {
	t.Helper()

	var session model.UserSession
	require.NoError(t, db.Where("refresh_token_hash = ?", hashTokenForTest(refreshToken)).First(&session).Error)
	return session
}

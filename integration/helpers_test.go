//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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
	"paigram/internal/config"
	"paigram/internal/email"
	"paigram/internal/middleware"
	"paigram/internal/model"
	"paigram/internal/response"
	"paigram/internal/router"
	"paigram/internal/sessioncache"
)

type integrationEnv struct {
	MySQLAddr     string
	MySQLUser     string
	MySQLPassword string
	MySQLDatabase string
	MySQLConfig   string
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	RedisPrefix   string
}

type integrationStack struct {
	Env         integrationEnv
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
	t.Helper()

	env := loadIntegrationEnv(t)
	stack := &integrationStack{Env: env}

	dbName := uniqueDatabaseName(t.Name(), env.MySQLDatabase)
	rootDB := openMySQLRootDB(t, env)
	createDatabase(t, rootDB, dbName)
	stack.cleanup = append(stack.cleanup, func() {
		dropDatabase(t, rootDB, dbName)
		_ = rootDB.Close()
	})

	stack.DatabaseCfg = config.DatabaseConfig{
		Addr:          env.MySQLAddr,
		Username:      env.MySQLUser,
		Password:      env.MySQLPassword,
		Dbname:        dbName,
		Config:        env.MySQLConfig,
		MigrationsDir: migrationsDir(t),
		AutoMigrate:   false,
		AutoSeed:      false,
	}

	stack.SQLDB = openMySQLDatabase(t, stack.DatabaseCfg)
	stack.cleanup = append(stack.cleanup, func() {
		_ = stack.SQLDB.Close()
	})

	runMigrations(t, stack.SQLDB, stack.DatabaseCfg)

	var err error
	stack.DB, err = gorm.Open(gormmysql.Open(buildMySQLDSN(stack.DatabaseCfg)), &gorm.Config{})
	require.NoError(t, err)

	stack.RedisPrefix = uniqueRedisPrefix(t.Name(), env.RedisPrefix)
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

	stack.Router = router.New(newTestConfig(env, stack.RedisPrefix), sessionStore, stack.DB, rateLimitStore, stack.Email)

	t.Cleanup(func() {
		for i := len(stack.cleanup) - 1; i >= 0; i-- {
			stack.cleanup[i]()
		}
	})

	return stack
}

func loadIntegrationEnv(t *testing.T) integrationEnv {
	t.Helper()

	env := integrationEnv{
		MySQLAddr:     os.Getenv("PAI_DATABASE_ADDR"),
		MySQLUser:     os.Getenv("PAI_DATABASE_USERNAME"),
		MySQLPassword: os.Getenv("PAI_DATABASE_PASSWORD"),
		MySQLDatabase: os.Getenv("PAI_DATABASE_DBNAME"),
		MySQLConfig:   os.Getenv("PAI_DATABASE_CONFIG"),
		RedisAddr:     os.Getenv("PAI_REDIS_ADDR"),
		RedisPassword: os.Getenv("PAI_REDIS_PASSWORD"),
		RedisPrefix:   os.Getenv("PAI_REDIS_PREFIX"),
	}

	if env.MySQLConfig == "" {
		env.MySQLConfig = "charset=utf8mb4&parseTime=True&loc=UTC&multiStatements=true"
	}
	if env.RedisPrefix == "" {
		env.RedisPrefix = "itest"
	}

	missing := make([]string, 0, 5)
	if env.MySQLAddr == "" {
		missing = append(missing, "PAI_DATABASE_ADDR")
	}
	if env.MySQLUser == "" {
		missing = append(missing, "PAI_DATABASE_USERNAME")
	}
	if env.MySQLPassword == "" {
		missing = append(missing, "PAI_DATABASE_PASSWORD")
	}
	if env.MySQLDatabase == "" {
		missing = append(missing, "PAI_DATABASE_DBNAME")
	}
	if env.RedisAddr == "" {
		missing = append(missing, "PAI_REDIS_ADDR")
	}
	if len(missing) > 0 {
		t.Skipf("integration env not configured: missing %s", strings.Join(missing, ", "))
	}

	return env
}

func newTestConfig(env integrationEnv, redisPrefix string) *config.Config {
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

func openMySQLRootDB(t *testing.T, env integrationEnv) *sql.DB {
	t.Helper()

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/?%s", env.MySQLUser, env.MySQLPassword, env.MySQLAddr, trimQueryPrefix(env.MySQLConfig)))
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

func openRedis(t *testing.T, env integrationEnv) *redis.Client {
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

func migrationsDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	return filepath.Join(wd, "..", "initialize", "migrate", "sql")
}

func performJSONRequest(t *testing.T, handler http.Handler, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *strings.Reader
	if body == nil {
		reader = strings.NewReader("")
	} else {
		payload, err := json.Marshal(body)
		require.NoError(t, err)
		reader = strings.NewReader(string(payload))
	}

	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func decodeResponseData(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var resp response.Response
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &resp))
	data, ok := resp.Data.(map[string]any)
	require.True(t, ok, "expected map response data, got %T", resp.Data)
	return data
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

func uniqueDatabaseName(testName, base string) string {
	baseName := sanitizeName(base)
	if len(baseName) > 12 {
		baseName = baseName[:12]
	}
	return fmt.Sprintf("t_%s_%s_%s", baseName, shortHash(testName), shortHash(fmt.Sprintf("%d", time.Now().UnixNano())))
}

func uniqueRedisPrefix(testName, base string) string {
	baseName := sanitizeName(base)
	if len(baseName) > 16 {
		baseName = baseName[:16]
	}
	return fmt.Sprintf("%s:%s:%s", baseName, shortHash(testName), shortHash(fmt.Sprintf("%d", time.Now().UnixNano())))
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:8]
}

func sanitizeName(value string) string {
	value = strings.ToLower(value)
	replacer := strings.NewReplacer("/", "_", "\\", "_", " ", "_", "-", "_", ":", "_", ".", "_")
	value = replacer.Replace(value)
	value = strings.Trim(value, "_")
	if value == "" {
		return "itest"
	}
	return value
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

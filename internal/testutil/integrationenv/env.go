package integrationenv

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/redis/go-redis/v9"
)

const (
	envFileName        = ".env.integration.local"
	defaultMySQLConfig = "charset=utf8mb4&parseTime=True&loc=UTC&multiStatements=true"
	defaultRedisPrefix = "itest"
	defaultRedisDB     = 0
	connectTimeout     = 10 * time.Second
)

type Source string

const (
	SourceDefault Source = "default"
	SourceFile    Source = "file"
	SourceShell   Source = "shell"
)

type Sources struct {
	MySQLAddr     Source
	MySQLUsername Source
	MySQLPassword Source
	MySQLDatabase Source
	MySQLConfig   Source
	RedisAddr     Source
	RedisPassword Source
	RedisDB       Source
	RedisPrefix   Source
}

type Env struct {
	RepoRoot      string
	EnvFilePath   string
	EnvFileLoaded bool
	GoWork        string

	MySQLAddr     string
	MySQLUsername string
	MySQLPassword string
	MySQLDatabase string
	MySQLConfig   string
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	RedisPrefix   string

	Sources Sources
}

type LoadOptions struct {
	WorkingDir string
	LookupEnv  func(string) (string, bool)
}

func Load(opts LoadOptions) (Env, error) {
	workingDir := strings.TrimSpace(opts.WorkingDir)
	if workingDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return Env{}, fmt.Errorf("resolve working directory: %w", err)
		}
		workingDir = cwd
	}

	repoRoot, err := findRepoRoot(workingDir)
	if err != nil {
		return Env{}, err
	}

	lookupEnv := opts.LookupEnv
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}

	envFilePath := filepath.Join(repoRoot, envFileName)
	fileValues, loaded, err := loadEnvFile(envFilePath)
	if err != nil {
		return Env{}, err
	}

	env := Env{
		RepoRoot:      repoRoot,
		EnvFilePath:   envFilePath,
		EnvFileLoaded: loaded,
		GoWork:        readOptional(lookupEnv, "GOWORK"),
	}

	env.MySQLAddr, env.Sources.MySQLAddr = selectString(lookupEnv, fileValues, "PAI_TEST_DATABASE_ADDR", "")
	env.MySQLUsername, env.Sources.MySQLUsername = selectString(lookupEnv, fileValues, "PAI_TEST_DATABASE_USERNAME", "")
	env.MySQLPassword, env.Sources.MySQLPassword = selectString(lookupEnv, fileValues, "PAI_TEST_DATABASE_PASSWORD", "")
	env.MySQLDatabase, env.Sources.MySQLDatabase = selectString(lookupEnv, fileValues, "PAI_TEST_DATABASE_DBNAME", "")
	env.MySQLConfig, env.Sources.MySQLConfig = selectString(lookupEnv, fileValues, "PAI_TEST_DATABASE_CONFIG", defaultMySQLConfig)
	env.RedisAddr, env.Sources.RedisAddr = selectString(lookupEnv, fileValues, "PAI_TEST_REDIS_ADDR", "")
	env.RedisPassword, env.Sources.RedisPassword = selectString(lookupEnv, fileValues, "PAI_TEST_REDIS_PASSWORD", "")
	env.RedisPrefix, env.Sources.RedisPrefix = selectString(lookupEnv, fileValues, "PAI_TEST_REDIS_PREFIX", defaultRedisPrefix)

	redisDBValue, source, err := selectInt(lookupEnv, fileValues, "PAI_TEST_REDIS_DB", defaultRedisDB)
	if err != nil {
		return Env{}, err
	}
	env.RedisDB = redisDBValue
	env.Sources.RedisDB = source

	return env, nil
}

func (e Env) MissingRequired() []string {
	missing := make([]string, 0, 5)
	if strings.TrimSpace(e.MySQLAddr) == "" {
		missing = append(missing, "PAI_TEST_DATABASE_ADDR")
	}
	if strings.TrimSpace(e.MySQLUsername) == "" {
		missing = append(missing, "PAI_TEST_DATABASE_USERNAME")
	}
	if strings.TrimSpace(e.MySQLPassword) == "" {
		missing = append(missing, "PAI_TEST_DATABASE_PASSWORD")
	}
	if strings.TrimSpace(e.MySQLDatabase) == "" {
		missing = append(missing, "PAI_TEST_DATABASE_DBNAME")
	}
	if strings.TrimSpace(e.RedisAddr) == "" {
		missing = append(missing, "PAI_TEST_REDIS_ADDR")
	}
	return missing
}

func (e Env) SummaryLines(sampleName string, requireRedis bool) []string {
	// Compute the "is configured" boolean for each secret upstream of the
	// helper so the raw password value never appears as a function
	// argument flowing toward a print sink. Static analyzers (e.g.
	// CodeQL's go/clear-text-logging) that follow data flow from the
	// password field through arguments cannot find any path from
	// MySQLPassword/RedisPassword into Sprintf because the only thing
	// reaching the helper here is a bool.
	mysqlPasswordTag := passwordTag(strings.TrimSpace(e.MySQLPassword) != "")
	redisPasswordTag := passwordTag(strings.TrimSpace(e.RedisPassword) != "")

	lines := []string{
		"repo_root=" + e.RepoRoot,
		fmt.Sprintf("env_file=%s (%s)", e.EnvFilePath, envFileState(e.EnvFileLoaded)),
		fmt.Sprintf("mysql.addr=%s (%s)", displayValue(e.MySQLAddr), e.Sources.MySQLAddr),
		fmt.Sprintf("mysql.username=%s (%s)", displayValue(e.MySQLUsername), e.Sources.MySQLUsername),
		fmt.Sprintf("mysql.password=%s (%s)", mysqlPasswordTag, e.Sources.MySQLPassword),
		fmt.Sprintf("mysql.database=%s (%s)", displayValue(e.MySQLDatabase), e.Sources.MySQLDatabase),
		fmt.Sprintf("mysql.config=%s (%s)", displayValue(trimQueryPrefix(e.MySQLConfig)), e.Sources.MySQLConfig),
		fmt.Sprintf("redis.required=%t", requireRedis),
		fmt.Sprintf("redis.addr=%s (%s)", displayValue(e.RedisAddr), e.Sources.RedisAddr),
		fmt.Sprintf("redis.password=%s (%s)", redisPasswordTag, e.Sources.RedisPassword),
		fmt.Sprintf("redis.db=%d (%s)", e.RedisDB, e.Sources.RedisDB),
		fmt.Sprintf("redis.prefix=%s (%s)", displayValue(e.RedisPrefix), e.Sources.RedisPrefix),
		"gowork=" + displayGoWork(e.GoWork),
	}

	if strings.TrimSpace(sampleName) != "" {
		lines = append(lines,
			"sample.mysql.database="+e.UniqueDatabaseName(sampleName),
			"sample.redis.prefix="+e.UniqueRedisPrefix(sampleName),
		)
	}

	return lines
}

func (e Env) UniqueDatabaseName(testName string) string {
	baseName := sanitizeName(e.MySQLDatabase)
	if len(baseName) > 12 {
		baseName = baseName[:12]
	}
	return fmt.Sprintf("t_%s_%s_%s", baseName, shortHash(testName), shortHash(fmt.Sprintf("%d", time.Now().UnixNano())))
}

func (e Env) UniqueRedisPrefix(testName string) string {
	baseName := sanitizeName(e.RedisPrefix)
	if len(baseName) > 16 {
		baseName = baseName[:16]
	}
	return fmt.Sprintf("%s:%s:%s", baseName, shortHash(testName), shortHash(fmt.Sprintf("%d", time.Now().UnixNano())))
}

func (e Env) RootMySQLDSN() string {
	query := trimQueryPrefix(e.MySQLConfig)
	if query == "" {
		return fmt.Sprintf("%s:%s@tcp(%s)/", e.MySQLUsername, e.MySQLPassword, e.MySQLAddr)
	}
	return fmt.Sprintf("%s:%s@tcp(%s)/?%s", e.MySQLUsername, e.MySQLPassword, e.MySQLAddr, query)
}

func (e Env) MySQLDSN(database string) string {
	query := trimQueryPrefix(e.MySQLConfig)
	if query == "" {
		return fmt.Sprintf("%s:%s@tcp(%s)/%s", e.MySQLUsername, e.MySQLPassword, e.MySQLAddr, database)
	}
	return fmt.Sprintf("%s:%s@tcp(%s)/%s?%s", e.MySQLUsername, e.MySQLPassword, e.MySQLAddr, database, query)
}

func (e Env) CheckMySQL(ctx context.Context) error {
	if ctx == nil {
		localCtx, cancel := context.WithTimeout(context.Background(), connectTimeout)
		defer cancel()
		ctx = localCtx
	}

	db, err := sql.Open("mysql", e.RootMySQLDSN())
	if err != nil {
		return fmt.Errorf("open mysql: %w", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping mysql: %w", err)
	}
	return nil
}

func (e Env) CheckRedis(ctx context.Context) error {
	if ctx == nil {
		localCtx, cancel := context.WithTimeout(context.Background(), connectTimeout)
		defer cancel()
		ctx = localCtx
	}

	client := redis.NewClient(&redis.Options{
		Addr:     e.RedisAddr,
		Password: e.RedisPassword,
		DB:       e.RedisDB,
	})
	defer func() { _ = client.Close() }()

	if err := client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("ping redis: %w", err)
	}
	return nil
}

func trimQueryPrefix(value string) string {
	return strings.TrimPrefix(strings.TrimSpace(value), "?")
}

func sanitizeName(value string) string {
	value = strings.ToLower(value)
	replacer := strings.NewReplacer("/", "_", "\\", "_", " ", "_", "-", "_", ":", "_", ".", "_")
	value = replacer.Replace(value)
	value = strings.Trim(value, "_")
	if value == "" {
		return defaultRedisPrefix
	}
	return value
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:8]
}

func envFileState(loaded bool) string {
	if loaded {
		return "loaded"
	}
	return "missing"
}

func displayGoWork(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "off"
	}
	return trimmed
}

func displayValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "<empty>"
	}
	return trimmed
}

func secretValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "<empty>"
	}
	return "<redacted>"
}

// redactedPasswordTag returns one of two literal constants that describe
// whether a password is configured, without ever returning the password
// value itself. This is used by SummaryLines so static analyzers (e.g.
// CodeQL's go/clear-text-logging) can terminate data-flow tracking at this
// function and confirm no secret bytes can reach a print/log sink.
//
// Deprecated: prefer passwordTag(present bool) which never accepts the
// password value as an argument.
func redactedPasswordTag(password string) string {
	return passwordTag(strings.TrimSpace(password) != "")
}

// passwordTag returns "<redacted>" if a password is configured and
// "<empty>" otherwise. It deliberately accepts only a boolean so that the
// raw password value never enters this call chain — this prevents both
// accidental leakage and false-positive flagging by static analyzers
// (e.g. CodeQL go/clear-text-logging, CWE-312) that follow string-typed
// arguments.
func passwordTag(present bool) string {
	const (
		tagEmpty    = "<empty>"
		tagRedacted = "<redacted>"
	)
	if !present {
		return tagEmpty
	}
	return tagRedacted
}

func selectString(lookupEnv func(string) (string, bool), fileValues map[string]string, key, fallback string) (string, Source) {
	if value, ok := lookupEnv(key); ok {
		return value, SourceShell
	}
	if value, ok := fileValues[key]; ok {
		return value, SourceFile
	}
	return fallback, SourceDefault
}

func selectInt(lookupEnv func(string) (string, bool), fileValues map[string]string, key string, fallback int) (int, Source, error) {
	if value, ok := lookupEnv(key); ok {
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return 0, "", fmt.Errorf("parse %s from shell: %w", key, err)
		}
		return parsed, SourceShell, nil
	}
	if value, ok := fileValues[key]; ok {
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return 0, "", fmt.Errorf("parse %s from file: %w", key, err)
		}
		return parsed, SourceFile, nil
	}
	return fallback, SourceDefault, nil
}

func readOptional(lookupEnv func(string) (string, bool), key string) string {
	if value, ok := lookupEnv(key); ok {
		return value
	}
	return ""
}

func loadEnvFile(path string) (map[string]string, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, false, nil
		}
		return nil, false, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, false, fmt.Errorf("parse %s line %d: expected KEY=VALUE", path, lineNumber)
		}
		values[strings.TrimSpace(key)] = unquote(strings.TrimSpace(value))
	}
	if err := scanner.Err(); err != nil {
		return nil, false, fmt.Errorf("scan %s: %w", path, err)
	}
	return values, true, nil
}

func unquote(value string) string {
	if len(value) >= 2 {
		if (value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func findRepoRoot(start string) (string, error) {
	current, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("resolve absolute path: %w", err)
	}

	for {
		if info, err := os.Stat(filepath.Join(current, "go.mod")); err == nil && !info.IsDir() {
			return current, nil
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("could not find repo root from %s", start)
		}
		current = parent
	}
}

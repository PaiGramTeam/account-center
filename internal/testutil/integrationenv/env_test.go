package integrationenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadUsesEnvFileDefaultsAndTracksSources(t *testing.T) {
	repoRoot := newTempRepoRoot(t, "PAI_TEST_DATABASE_ADDR=127.0.0.1:3306\nPAI_TEST_DATABASE_USERNAME=test_user\nPAI_TEST_DATABASE_PASSWORD=file-secret\nPAI_TEST_DATABASE_DBNAME=acctest\nPAI_TEST_REDIS_ADDR=127.0.0.1:6379\n")

	env, err := Load(LoadOptions{
		WorkingDir: filepath.Join(repoRoot, "integration"),
		LookupEnv:  emptyLookupEnv,
	})
	require.NoError(t, err)

	require.Equal(t, repoRoot, env.RepoRoot)
	require.Equal(t, filepath.Join(repoRoot, envFileName), env.EnvFilePath)
	require.True(t, env.EnvFileLoaded)
	require.Equal(t, "127.0.0.1:3306", env.MySQLAddr)
	require.Equal(t, "test_user", env.MySQLUsername)
	require.Equal(t, "file-secret", env.MySQLPassword)
	require.Equal(t, "acctest", env.MySQLDatabase)
	require.Equal(t, defaultMySQLConfig, env.MySQLConfig)
	require.Equal(t, "127.0.0.1:6379", env.RedisAddr)
	require.Equal(t, "", env.RedisPassword)
	require.Equal(t, 0, env.RedisDB)
	require.Equal(t, defaultRedisPrefix, env.RedisPrefix)
	require.Equal(t, "", env.GoWork)

	require.Equal(t, SourceFile, env.Sources.MySQLAddr)
	require.Equal(t, SourceFile, env.Sources.MySQLUsername)
	require.Equal(t, SourceFile, env.Sources.MySQLCredentialOrigin)
	require.Equal(t, SourceFile, env.Sources.MySQLDatabase)
	require.Equal(t, SourceDefault, env.Sources.MySQLConfig)
	require.Equal(t, SourceFile, env.Sources.RedisAddr)
	require.Equal(t, SourceDefault, env.Sources.RedisCredentialOrigin)
	require.Equal(t, SourceDefault, env.Sources.RedisDB)
	require.Equal(t, SourceDefault, env.Sources.RedisPrefix)
	require.Empty(t, env.MissingRequired())

	require.True(t, env.HasMySQLPassword, "MySQLPassword presence flag should be true when set")
	require.False(t, env.HasRedisPassword, "RedisPassword presence flag should be false when empty")

	lines := strings.Join(env.SummaryLines("doctor", true), "\n")
	require.Contains(t, lines, "mysql.addr=127.0.0.1:3306 (file)")
	require.Contains(t, lines, "mysql.password=<redacted> (file)")
	require.Contains(t, lines, "mysql.config="+defaultMySQLConfig+" (default)")
	require.Contains(t, lines, "redis.required=true")
	require.Contains(t, lines, "redis.prefix="+defaultRedisPrefix+" (default)")
	require.Contains(t, lines, "gowork=off")
	require.NotContains(t, lines, "file-secret")

	dbName := env.UniqueDatabaseName("Test/Load Uses Env File")
	redisPrefix := env.UniqueRedisPrefix("Test/Load Uses Env File")
	require.Contains(t, dbName, "acctest")
	require.Contains(t, redisPrefix, defaultRedisPrefix)
	require.NotContains(t, dbName, "/")
	require.NotContains(t, redisPrefix, "/")
}

func TestLoadShellEnvOverridesFileValues(t *testing.T) {
	repoRoot := newTempRepoRoot(t, "PAI_TEST_DATABASE_ADDR=file-host:3306\nPAI_TEST_DATABASE_USERNAME=file-user\nPAI_TEST_DATABASE_PASSWORD=file-secret\nPAI_TEST_DATABASE_DBNAME=file-db\nPAI_TEST_REDIS_ADDR=file-redis:6379\nPAI_TEST_REDIS_PASSWORD=file-redis-secret\nPAI_TEST_REDIS_PREFIX=file-prefix\n")

	env, err := Load(LoadOptions{
		WorkingDir: filepath.Join(repoRoot, "integration"),
		LookupEnv: mapLookupEnv(map[string]string{
			"PAI_TEST_DATABASE_ADDR":     "shell-host:3306",
			"PAI_TEST_DATABASE_USERNAME": "shell-user",
			"PAI_TEST_DATABASE_PASSWORD": "shell-secret",
			"PAI_TEST_DATABASE_DBNAME":   "shell-db",
			"PAI_TEST_DATABASE_CONFIG":   "?parseTime=True",
			"PAI_TEST_REDIS_ADDR":        "shell-redis:6379",
			"PAI_TEST_REDIS_PASSWORD":    "shell-redis-secret",
			"PAI_TEST_REDIS_DB":          "5",
			"PAI_TEST_REDIS_PREFIX":      "shell-prefix",
			"GOWORK":                     filepath.Join(repoRoot, "go.work"),
		}),
	})
	require.NoError(t, err)

	require.Equal(t, "shell-host:3306", env.MySQLAddr)
	require.Equal(t, "shell-user", env.MySQLUsername)
	require.Equal(t, "shell-secret", env.MySQLPassword)
	require.Equal(t, "shell-db", env.MySQLDatabase)
	require.Equal(t, "?parseTime=True", env.MySQLConfig)
	require.Equal(t, "shell-redis:6379", env.RedisAddr)
	require.Equal(t, "shell-redis-secret", env.RedisPassword)
	require.Equal(t, 5, env.RedisDB)
	require.Equal(t, "shell-prefix", env.RedisPrefix)
	require.Equal(t, filepath.Join(repoRoot, "go.work"), env.GoWork)

	require.Equal(t, SourceShell, env.Sources.MySQLAddr)
	require.Equal(t, SourceShell, env.Sources.MySQLUsername)
	require.Equal(t, SourceShell, env.Sources.MySQLCredentialOrigin)
	require.Equal(t, SourceShell, env.Sources.MySQLDatabase)
	require.Equal(t, SourceShell, env.Sources.MySQLConfig)
	require.Equal(t, SourceShell, env.Sources.RedisAddr)
	require.Equal(t, SourceShell, env.Sources.RedisCredentialOrigin)
	require.Equal(t, SourceShell, env.Sources.RedisDB)
	require.Equal(t, SourceShell, env.Sources.RedisPrefix)

	require.True(t, env.HasMySQLPassword)
	require.True(t, env.HasRedisPassword)

	lines := strings.Join(env.SummaryLines("doctor", true), "\n")
	require.Contains(t, lines, "mysql.addr=shell-host:3306 (shell)")
	require.Contains(t, lines, "redis.required=true")
	require.Contains(t, lines, "redis.db=5 (shell)")
	require.Contains(t, lines, "gowork="+filepath.Join(repoRoot, "go.work"))
	require.NotContains(t, lines, "shell-secret")
	require.NotContains(t, lines, "shell-redis-secret")
}

func TestLoadReportsMissingRequiredFields(t *testing.T) {
	repoRoot := newTempRepoRoot(t, "PAI_TEST_DATABASE_ADDR=127.0.0.1:3306\n")

	env, err := Load(LoadOptions{
		WorkingDir: filepath.Join(repoRoot, "integration"),
		LookupEnv:  emptyLookupEnv,
	})
	require.NoError(t, err)
	require.Equal(t, []string{
		"PAI_TEST_DATABASE_USERNAME",
		"PAI_TEST_DATABASE_PASSWORD",
		"PAI_TEST_DATABASE_DBNAME",
		"PAI_TEST_REDIS_ADDR",
	}, env.MissingRequired())
}

func newTempRepoRoot(t *testing.T, envFile string) string {
	t.Helper()

	repoRoot := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(repoRoot, "integration"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(repoRoot, "go.mod"), []byte("module paigram\n\ngo 1.25.7\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(repoRoot, envFileName), []byte(envFile), 0o644))
	return repoRoot
}

func emptyLookupEnv(string) (string, bool) {
	return "", false
}

func mapLookupEnv(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

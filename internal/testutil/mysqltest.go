package testutil

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type MySQLEnv struct {
	Addr     string
	User     string
	Password string
	Database string
	Config   string
}

func LoadMySQLTestEnv(t *testing.T) MySQLEnv {
	t.Helper()

	env := MySQLEnv{
		Addr:     os.Getenv("PAI_DATABASE_ADDR"),
		User:     os.Getenv("PAI_DATABASE_USERNAME"),
		Password: os.Getenv("PAI_DATABASE_PASSWORD"),
		Database: os.Getenv("PAI_DATABASE_DBNAME"),
		Config:   os.Getenv("PAI_DATABASE_CONFIG"),
	}
	if env.Config == "" {
		env.Config = "charset=utf8mb4&parseTime=True&loc=UTC&multiStatements=true"
	}

	missing := make([]string, 0, 4)
	if env.Addr == "" {
		missing = append(missing, "PAI_DATABASE_ADDR")
	}
	if env.User == "" {
		missing = append(missing, "PAI_DATABASE_USERNAME")
	}
	if env.Password == "" {
		missing = append(missing, "PAI_DATABASE_PASSWORD")
	}
	if env.Database == "" {
		missing = append(missing, "PAI_DATABASE_DBNAME")
	}
	if len(missing) > 0 {
		t.Skipf("mysql test env not configured: missing %s", strings.Join(missing, ", "))
	}

	return env
}

func OpenMySQLTestDB(t *testing.T, prefix string, models ...any) *gorm.DB {
	t.Helper()

	env := LoadMySQLTestEnv(t)
	rootDB := openRootDB(t, env)
	dbName := uniqueDBName(prefix)
	createDatabase(t, rootDB, dbName)
	t.Cleanup(func() {
		dropDatabase(t, rootDB, dbName)
		_ = rootDB.Close()
	})

	db, err := gorm.Open(mysql.Open(buildDSN(env, dbName)), &gorm.Config{})
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})

	if len(models) > 0 {
		require.NoError(t, db.AutoMigrate(models...))
	}

	return db
}

func openRootDB(t *testing.T, env MySQLEnv) *sql.DB {
	t.Helper()
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/?%s", env.User, env.Password, env.Addr, trimQuery(env.Config)))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	require.NoError(t, db.PingContext(ctx))

	return db
}

func createDatabase(t *testing.T, db *sql.DB, dbName string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", dbName))
	require.NoError(t, err)
}

func dropDatabase(t *testing.T, db *sql.DB, dbName string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", dbName))
	require.NoError(t, err)
}

func buildDSN(env MySQLEnv, dbName string) string {
	return fmt.Sprintf("%s:%s@tcp(%s)/%s?%s", env.User, env.Password, env.Addr, dbName, trimQuery(env.Config))
}

func trimQuery(value string) string {
	return strings.TrimPrefix(strings.TrimSpace(value), "?")
}

func uniqueDBName(prefix string) string {
	buf := make([]byte, 4)
	_, _ = rand.Read(buf)
	prefix = sanitize(prefix)
	if len(prefix) > 20 {
		prefix = prefix[:20]
	}
	return fmt.Sprintf("t_%s_%s", prefix, hex.EncodeToString(buf))
}

func sanitize(value string) string {
	value = strings.ToLower(value)
	replacer := strings.NewReplacer("/", "_", "\\", "_", " ", "_", "-", "_", ":", "_", ".", "_")
	value = replacer.Replace(value)
	value = strings.Trim(value, "_")
	if value == "" {
		return "mysql"
	}
	return value
}

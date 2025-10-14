package migrate

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	migrate "github.com/golang-migrate/migrate/v4"
	mysqlmigrate "github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	"paigram/internal/config"
)

// Run applies filesystem-backed migrations using golang-migrate.
func Run(sqlDB *sql.DB, cfg config.DatabaseConfig) (err error) {
	dir := strings.TrimSpace(cfg.MigrationsDir)
	if dir == "" {
		return fmt.Errorf("database.migrations_dir cannot be empty when auto_migrate is enabled")
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve migrations dir: %w", err)
	}

	if _, statErr := os.Stat(absDir); statErr != nil {
		return fmt.Errorf("access migrations dir %q: %w", absDir, statErr)
	}

	driver, err := mysqlmigrate.WithInstance(sqlDB, &mysqlmigrate.Config{})
	if err != nil {
		return fmt.Errorf("initialise mysql migration driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance("file://"+filepath.ToSlash(absDir), cfg.Dbname, driver)
	if err != nil {
		return fmt.Errorf("create migration instance: %w", err)
	}

	defer func() {
		sourceErr, dbErr := m.Close()
		if err != nil {
			return
		}
		switch {
		case sourceErr != nil && dbErr != nil:
			err = fmt.Errorf("close migration source: %v; database: %w", sourceErr, dbErr)
		case sourceErr != nil:
			err = fmt.Errorf("close migration source: %w", sourceErr)
		case dbErr != nil:
			err = fmt.Errorf("close migration database: %w", dbErr)
		}
	}()

	if err = m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("apply migrations: %w", err)
	}

	return nil
}

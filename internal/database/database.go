package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"paigram/initialize"
	initmigrate "paigram/initialize/migrate"
	"paigram/internal/config"
	"paigram/internal/logging"
)

var (
	dbInstance *gorm.DB
	dbOnce     sync.Once
)

// Connect initialises a GORM connection using the provided configuration.
// security is consulted when AutoSeed is enabled so the bootstrap admin
// password is hashed at the operator-configured cost (V8).
func Connect(cfg config.DatabaseConfig, security config.SecurityConfig) (*gorm.DB, error) {
	var initErr error
	dbOnce.Do(func() {
		if err := validateConfig(cfg); err != nil {
			initErr = err
			return
		}

		gormLogger, err := newGormLogger(cfg)
		if err != nil {
			initErr = err
			return
		}

		gormCfg := &gorm.Config{Logger: gormLogger}

		dsn := buildDSN(cfg)
		db, err := gorm.Open(gormmysql.Open(dsn), gormCfg)
		if err != nil {
			initErr = fmt.Errorf("open database: %w", err)
			return
		}

		dbInstance = db

		sqlDB, err := db.DB()
		if err != nil {
			initErr = fmt.Errorf("obtain database handle: %w", err)
			return
		}

		if cfg.MaxIdleConns > 0 {
			sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
		}
		if cfg.MaxOpenConns > 0 {
			sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
		}

		if cfg.AutoMigrate || cfg.AutoSeed {
			// Run initialization in a separate connection to avoid connection closing issues
			if cfg.AutoMigrate {
				log.Println("Running database migrations...")
				// Create a separate connection for migrations
				migrationDB, err := sql.Open("mysql", dsn)
				if err != nil {
					initErr = fmt.Errorf("open migration database: %w", err)
					return
				}
				defer migrationDB.Close()

				if err := initmigrate.Run(migrationDB, cfg); err != nil {
					initErr = fmt.Errorf("run migrations: %w", err)
					return
				}
				log.Println("Database migrations completed successfully")
			}

			if cfg.AutoSeed {
				// Use the GORM connection for seeding
				initializer := initialize.NewInitializer(db, nil, cfg, security)
				if err := initializer.Run(); err != nil {
					initErr = fmt.Errorf("run seed data: %w", err)
					return
				}
			}
		}
	})

	if initErr != nil {
		Reset()
		return nil, initErr
	}

	return dbInstance, nil
}

// MustConnect is a convenience helper that panics when connection fails.
// The security config is consulted only when cfg.AutoSeed is true.
func MustConnect(cfg config.DatabaseConfig, security config.SecurityConfig) *gorm.DB {
	db, err := Connect(cfg, security)
	if err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	return db
}

// Get returns the active gorm database instance.
func Get() *gorm.DB {
	if dbInstance == nil {
		log.Fatal("database connection has not been initialised")
	}
	return dbInstance
}

// Reset clears the cached instance (useful for tests).
func Reset() {
	dbInstance = nil
	dbOnce = sync.Once{}
}

func validateConfig(cfg config.DatabaseConfig) error {
	var missing []string
	if strings.TrimSpace(cfg.Addr) == "" {
		missing = append(missing, "database.addr")
	}
	if strings.TrimSpace(cfg.Username) == "" {
		missing = append(missing, "database.username")
	}
	if strings.TrimSpace(cfg.Password) == "" {
		missing = append(missing, "database.password")
	}
	if strings.TrimSpace(cfg.Dbname) == "" {
		missing = append(missing, "database.dbname")
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required database config: %s", strings.Join(missing, ", "))
	}
	return nil
}

func buildDSN(cfg config.DatabaseConfig) string {
	query := strings.TrimSpace(cfg.Config)
	if query == "" {
		return fmt.Sprintf("%s:%s@tcp(%s)/%s", cfg.Username, cfg.Password, cfg.Addr, cfg.Dbname)
	}

	if after, ok := strings.CutPrefix(query, "?"); ok {
		query = after
	}
	return fmt.Sprintf("%s:%s@tcp(%s)/%s?%s", cfg.Username, cfg.Password, cfg.Addr, cfg.Dbname, query)
}

func newGormLogger(cfg config.DatabaseConfig) (logger.Interface, error) {
	logLevel, err := parseLogLevel(cfg.LogMode)
	if err != nil {
		return nil, err
	}

	conf := logger.Config{
		SlowThreshold:             time.Duration(cfg.SlowThreshold) * time.Millisecond,
		LogLevel:                  logLevel,
		IgnoreRecordNotFoundError: true,
		ParameterizedQueries:      true,
		Colorful:                  false,
	}

	if cfg.LogZap {
		zapWriter, err := logging.NewZapWriter("gorm")
		if err != nil {
			return nil, err
		}
		return logger.New(zapWriter, conf), nil
	}

	std := log.New(os.Stdout, "[gorm] ", log.LstdFlags)
	return logger.New(&stdWriter{logger: std}, conf), nil
}

func parseLogLevel(mode string) (logger.LogLevel, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "silent":
		return logger.Silent, nil
	case "error":
		return logger.Error, nil
	case "warn":
		return logger.Warn, nil
	case "info", "":
		return logger.Info, nil
	case "debug":
		// GORM treats debug as info level with additional data, align with docs.
		return logger.Info, nil
	default:
		return logger.Info, fmt.Errorf("invalid database.log_mode %q", mode)
	}
}

type stdWriter struct {
	logger *log.Logger
}

func (w *stdWriter) Printf(format string, args ...interface{}) {
	w.logger.Printf(format, args...)
}

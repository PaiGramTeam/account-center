package initialize

import (
	"database/sql"
	"fmt"
	"log"

	"gorm.io/gorm"

	initmigrate "paigram/initialize/migrate"
	"paigram/initialize/seed"
	"paigram/internal/config"
)

// Initializer handles the database initialization process including migrations and seed data.
type Initializer struct {
	db       *gorm.DB
	sqlDB    *sql.DB
	dbConfig config.DatabaseConfig
	security config.SecurityConfig
}

// NewInitializer creates a new database initializer.
func NewInitializer(db *gorm.DB, sqlDB *sql.DB, dbConfig config.DatabaseConfig, security config.SecurityConfig) *Initializer {
	return &Initializer{
		db:       db,
		sqlDB:    sqlDB,
		dbConfig: dbConfig,
		security: security,
	}
}

// Run executes the initialization process including migrations and seed data.
func (i *Initializer) Run() error {
	// Run migrations if enabled and sqlDB is provided
	if i.dbConfig.AutoMigrate && i.sqlDB != nil {
		log.Println("Running database migrations...")
		if err := initmigrate.Run(i.sqlDB, i.dbConfig); err != nil {
			return fmt.Errorf("run migrations: %w", err)
		}
		log.Println("Database migrations completed successfully")
	}

	// Run seed data if enabled
	if i.dbConfig.AutoSeed {
		log.Println("Running seed data initialization...")

		if err := seed.Run(i.db); err != nil {
			return fmt.Errorf("seed core data: %w", err)
		}

		bcryptCost := i.security.BcryptCost
		if bcryptCost <= 0 {
			bcryptCost = seed.DefaultBcryptCost
		}
		if err := seed.CreateDefaultAdmin(i.db, bcryptCost); err != nil {
			return fmt.Errorf("create default admin: %w", err)
		}
	}

	return nil
}

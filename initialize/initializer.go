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
	db     *gorm.DB
	sqlDB  *sql.DB
	config config.DatabaseConfig
}

// NewInitializer creates a new database initializer.
func NewInitializer(db *gorm.DB, sqlDB *sql.DB, config config.DatabaseConfig) *Initializer {
	return &Initializer{
		db:     db,
		sqlDB:  sqlDB,
		config: config,
	}
}

// Run executes the initialization process including migrations and seed data.
func (i *Initializer) Run() error {
	// Run migrations if enabled and sqlDB is provided
	if i.config.AutoMigrate && i.sqlDB != nil {
		log.Println("Running database migrations...")
		if err := initmigrate.Run(i.sqlDB, i.config); err != nil {
			return fmt.Errorf("run migrations: %w", err)
		}
		log.Println("Database migrations completed successfully")
	}

	// Run seed data if enabled
	if i.config.AutoSeed {
		log.Println("Running seed data initialization...")

		if err := seed.Run(i.db); err != nil {
			return fmt.Errorf("seed core data: %w", err)
		}

		if err := seed.CreateDefaultAdmin(i.db); err != nil {
			return fmt.Errorf("create default admin: %w", err)
		}
	}

	return nil
}

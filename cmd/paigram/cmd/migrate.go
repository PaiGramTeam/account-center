package cmd

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	initmigrate "paigram/initialize/migrate"
	"paigram/internal/config"
	"paigram/internal/database"
)

// migrateCmd represents the migrate command group
var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run database migrations",
	Long:  `Commands for managing database schema migrations.`,
}

// migrateUpCmd runs migrations up
var migrateUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Apply all pending migrations",
	Long:  `Apply all pending database migrations to update the schema to the latest version.`,
	Run: func(cmd *cobra.Command, args []string) {
		runMigrateUp()
	},
}

// migrateStatusCmd shows migration status
var migrateStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show migration status",
	Long:  `Display the current migration version and list of applied/pending migrations.`,
	Run: func(cmd *cobra.Command, args []string) {
		showMigrationStatus()
	},
}

func init() {
	rootCmd.AddCommand(migrateCmd)
	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateStatusCmd)
}

func runMigrateUp() {
	cfg := config.MustLoad("config")

	// Get raw database connection
	db := database.MustConnect(cfg.Database, cfg.Security)
	sqlDB, err := db.DB()
	if err != nil {
		fmt.Printf("Error getting database handle: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Running database migrations...")
	fmt.Printf("Migrations directory: %s\n", cfg.Database.MigrationsDir)
	fmt.Println()

	if err := initmigrate.Run(sqlDB, cfg.Database); err != nil {
		fmt.Printf("Error running migrations: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Migrations completed successfully!")
}

func showMigrationStatus() {
	cfg := config.MustLoad("config")

	// Get raw database connection
	db := database.MustConnect(cfg.Database, cfg.Security)
	sqlDB, err := db.DB()
	if err != nil {
		fmt.Printf("Error getting database handle: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Migration Status:")
	fmt.Println("-----------------")

	// Query current version from schema_migrations table
	var version sql.NullInt64
	var dirty sql.NullBool

	err = sqlDB.QueryRow(`
		SELECT version, dirty 
		FROM schema_migrations 
		ORDER BY version DESC 
		LIMIT 1
	`).Scan(&version, &dirty)

	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println("No migrations have been applied yet.")
		} else {
			fmt.Printf("Error checking migration status: %v\n", err)
			fmt.Println("(The schema_migrations table may not exist yet)")
		}
		return
	}

	if version.Valid {
		fmt.Printf("Current version: %d\n", version.Int64)
		if dirty.Valid && dirty.Bool {
			fmt.Println("⚠️  WARNING: Database is in a dirty state!")
			fmt.Println("The last migration may have failed. Please check and fix manually.")
		}
	} else {
		fmt.Println("No version information found.")
	}

	fmt.Println()
	fmt.Printf("Migrations directory: %s\n", cfg.Database.MigrationsDir)
}

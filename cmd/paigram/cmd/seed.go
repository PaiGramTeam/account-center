package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gorm.io/gorm"

	"paigram/initialize/seed"
	"paigram/internal/config"
)

// seedCmd represents the seed command
var seedCmd = &cobra.Command{
	Use:   "seed",
	Short: "Run database seed operations",
	Long:  `Run database seed operations to initialize permissions, roles, and optionally admin user.`,
}

// seedAllCmd runs all seed operations
var seedAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Run all seed operations",
	Long: `Run all seed operations including:
- Create default permissions
- Create default roles (Admin, Moderator, User, Guest)
- Create default admin user (if --with-admin flag is set)`,
	Run: func(cmd *cobra.Command, args []string) {
		runAllSeeds(cmd)
	},
}

// seedPermissionsCmd runs permission seeding only
var seedPermissionsCmd = &cobra.Command{
	Use:   "permissions",
	Short: "Create default permissions",
	Long:  `Create all default system permissions for user, role, bot, session, and audit management.`,
	Run: func(cmd *cobra.Command, args []string) {
		runPermissionSeeds()
	},
}

// seedRolesCmd runs role seeding only
var seedRolesCmd = &cobra.Command{
	Use:   "roles",
	Short: "Create default roles",
	Long:  `Create default system roles (Admin, Moderator, User, Guest) with their permissions.`,
	Run: func(cmd *cobra.Command, args []string) {
		runRoleSeeds()
	},
}

// seedAdminCmd creates default admin user
var seedAdminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Create default admin user",
	Long: `Create the default admin user from environment variables.

Environment variables:
- ADMIN_EMAIL    optional, defaults to admin@paigram.local
- ADMIN_PASSWORD REQUIRED — the seed step refuses to run when unset to
                  avoid leaking auto-generated passwords via logs.
- ADMIN_NAME     optional, defaults to "Administrator"`,
	Run: func(cmd *cobra.Command, args []string) {
		runAdminSeed()
	},
}

func init() {
	rootCmd.AddCommand(seedCmd)
	seedCmd.AddCommand(seedAllCmd)
	seedCmd.AddCommand(seedPermissionsCmd)
	seedCmd.AddCommand(seedRolesCmd)
	seedCmd.AddCommand(seedAdminCmd)

	// Flags for seed all
	seedAllCmd.Flags().Bool("with-admin", false, "Also create default admin user")
}

func runAllSeeds(cmd *cobra.Command) {
	db := getDB()

	fmt.Println("Running all seed operations...")
	fmt.Println()

	fmt.Println("1. Creating permissions, roles, and managed Casbin policies...")
	if err := seedRolesBootstrap(db); err != nil {
		fmt.Printf("Error running seed bootstrap: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Core seed data created successfully")
	fmt.Println()

	// Optionally create admin
	withAdmin, _ := cmd.Flags().GetBool("with-admin")
	if withAdmin {
		fmt.Println("2. Creating default admin user...")
		if err := seedAdminBootstrap(db); err != nil {
			fmt.Printf("Error creating default admin: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✓ Default admin processed successfully")
		fmt.Println("Email and password for the seeded admin came from")
		fmt.Println("ADMIN_EMAIL / ADMIN_PASSWORD environment variables.")
		fmt.Println("Rotate the password via the admin UI as soon as possible.")
	}

	fmt.Println("\n✅ All seed operations completed successfully!")
}

func runPermissionSeeds() {
	db := getDB()

	fmt.Println("Creating default permissions...")
	if err := seedPermissionsBootstrap(db); err != nil {
		fmt.Printf("Error seeding permissions: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Permissions created successfully!")
}

func runRoleSeeds() {
	db := getDB()

	fmt.Println("Creating default roles and managed Casbin policies...")
	if err := seedRolesBootstrap(db); err != nil {
		fmt.Printf("Error seeding roles: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Roles and managed Casbin policies created successfully!")
}

func runAdminSeed() {
	db := getDB()

	fmt.Println("Creating default admin user...")
	if err := seedAdminBootstrap(db); err != nil {
		fmt.Printf("Error creating default admin: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Default admin created successfully!")
	fmt.Println()
	fmt.Println("Default admin account created.")
	fmt.Println("- Email: ADMIN_EMAIL (defaults to admin@paigram.local)")
	fmt.Println("- Password: ADMIN_PASSWORD (the value you supplied via env)")
	fmt.Println()
	fmt.Println("⚠️  Rotate the password via the admin UI immediately.")
}

func seedPermissionsBootstrap(db *gorm.DB) error {
	return seed.SeedPermissions(db)
}

func seedRolesBootstrap(db *gorm.DB) error {
	return seed.Run(db)
}

func seedAdminBootstrap(db *gorm.DB) error {
	if err := seedRolesBootstrap(db); err != nil {
		return err
	}
	cfg := config.MustLoad("config")
	return seed.CreateDefaultAdmin(db, cfg.GetBcryptCost())
}

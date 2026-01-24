package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"paigram/initialize/seed"
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
	Long: `Create default admin user using environment variables or default credentials.
	
Environment variables:
- ADMIN_EMAIL: Admin email (default: admin@paigram.local)
- ADMIN_PASSWORD: Admin password (default: admin123456)
- ADMIN_NAME: Admin display name (default: Administrator)`,
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

	// Run permissions
	fmt.Println("1. Creating permissions...")
	if err := seed.SeedPermissions(db); err != nil {
		fmt.Printf("Error seeding permissions: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Permissions created successfully")
	fmt.Println()

	// Run roles
	fmt.Println("2. Creating roles...")
	if err := seed.SeedRoles(db); err != nil {
		fmt.Printf("Error seeding roles: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Roles created successfully")
	fmt.Println()

	// Optionally create admin
	withAdmin, _ := cmd.Flags().GetBool("with-admin")
	if withAdmin {
		fmt.Println("3. Creating default admin user...")
		if err := seed.CreateDefaultAdmin(db); err != nil {
			fmt.Printf("Error creating default admin: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✓ Default admin created successfully")
		fmt.Println("Email: admin@paigram.local")
		fmt.Println("Password: admin123456")
		fmt.Println("\n⚠️  Please change the default password immediately!")
	}

	fmt.Println("\n✅ All seed operations completed successfully!")
}

func runPermissionSeeds() {
	db := getDB()

	fmt.Println("Creating default permissions...")
	if err := seed.SeedPermissions(db); err != nil {
		fmt.Printf("Error seeding permissions: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Permissions created successfully!")
}

func runRoleSeeds() {
	db := getDB()

	fmt.Println("Creating default roles...")
	if err := seed.SeedRoles(db); err != nil {
		fmt.Printf("Error seeding roles: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Roles created successfully!")
}

func runAdminSeed() {
	db := getDB()

	fmt.Println("Creating default admin user...")
	if err := seed.CreateDefaultAdmin(db); err != nil {
		fmt.Printf("Error creating default admin: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Default admin created successfully!")
	fmt.Println()
	fmt.Println("Admin credentials:")
	fmt.Println("- Email: admin@paigram.local (or $ADMIN_EMAIL)")
	fmt.Println("- Password: admin123456 (or $ADMIN_PASSWORD)")
	fmt.Println()
	fmt.Println("⚠️  Please change the default password immediately!")
}

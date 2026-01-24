package cmd

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
	"gorm.io/gorm"

	"paigram/initialize/seed"
	"paigram/internal/model"
)

// adminCmd represents the admin command group
var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Manage administrator accounts",
	Long:  `Commands for managing administrator accounts in Paigram.`,
}

// adminCreateCmd represents the admin create command
var adminCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new administrator account",
	Long: `Create a new administrator account with specified email and password.
If no flags are provided, the command will prompt for the required information.`,
	Run: func(cmd *cobra.Command, args []string) {
		createAdmin(cmd)
	},
}

// adminListCmd represents the admin list command
var adminListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all administrator accounts",
	Long:  `List all users with administrator role.`,
	Run: func(cmd *cobra.Command, args []string) {
		listAdmins()
	},
}

// adminRemoveCmd represents the admin remove command
var adminRemoveCmd = &cobra.Command{
	Use:   "remove [email]",
	Short: "Remove administrator role from a user",
	Long:  `Remove administrator role from a user specified by email.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		removeAdmin(args[0])
	},
}

// adminResetPasswordCmd represents the admin reset-password command
var adminResetPasswordCmd = &cobra.Command{
	Use:   "reset-password [email]",
	Short: "Reset password for a user",
	Long: `Reset password for a user specified by email.
If no password is provided via flags, the command will prompt for a new password.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		resetPassword(args[0], cmd)
	},
}

func init() {
	rootCmd.AddCommand(adminCmd)
	adminCmd.AddCommand(adminCreateCmd)
	adminCmd.AddCommand(adminListCmd)
	adminCmd.AddCommand(adminRemoveCmd)
	adminCmd.AddCommand(adminResetPasswordCmd)

	// Flags for admin create
	adminCreateCmd.Flags().StringP("email", "e", "", "Administrator email")
	adminCreateCmd.Flags().StringP("password", "p", "", "Administrator password")
	adminCreateCmd.Flags().StringP("name", "n", "", "Administrator display name")
	adminCreateCmd.Flags().Bool("use-default", false, "Use default admin credentials from seed data")

	// Flags for admin reset-password
	adminResetPasswordCmd.Flags().StringP("password", "p", "", "New password (will prompt if not provided)")
	adminResetPasswordCmd.Flags().Bool("force", false, "Skip confirmation prompt")
}

func createAdmin(cmd *cobra.Command) {
	db := getDB()

	// Check if admin role exists
	var adminRole model.Role
	if err := db.Where("name = ?", model.RoleAdmin).First(&adminRole).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			fmt.Println("Admin role not found. Running seed data first...")
			if err := seed.SeedPermissions(db); err != nil {
				fmt.Printf("Error seeding permissions: %v\n", err)
				os.Exit(1)
			}
			if err := seed.SeedRoles(db); err != nil {
				fmt.Printf("Error seeding roles: %v\n", err)
				os.Exit(1)
			}
			// Retry getting admin role
			if err := db.Where("name = ?", model.RoleAdmin).First(&adminRole).Error; err != nil {
				fmt.Printf("Error finding admin role after seeding: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Printf("Error checking admin role: %v\n", err)
			os.Exit(1)
		}
	}

	// Check if using default credentials
	useDefault, _ := cmd.Flags().GetBool("use-default")
	if useDefault {
		if err := seed.CreateDefaultAdmin(db); err != nil {
			fmt.Printf("Error creating default admin: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Default admin account created successfully!")
		fmt.Println("Email: admin@paigram.local")
		fmt.Println("Password: admin123456")
		fmt.Println("\n⚠️  Please change the default password immediately!")
		return
	}

	// Get admin details
	email, _ := cmd.Flags().GetString("email")
	password, _ := cmd.Flags().GetString("password")
	name, _ := cmd.Flags().GetString("name")

	// Interactive mode if flags not provided
	if email == "" {
		email = promptInput("Email: ")
	}
	if password == "" {
		password = promptPassword("Password: ")
		confirmPassword := promptPassword("Confirm Password: ")
		if password != confirmPassword {
			fmt.Println("Passwords do not match!")
			os.Exit(1)
		}
	}
	if name == "" {
		name = promptInput("Display Name: ")
		if name == "" {
			name = "Administrator"
		}
	}

	// Validate email
	if !strings.Contains(email, "@") {
		fmt.Println("Invalid email format!")
		os.Exit(1)
	}

	// Check if user already exists
	var existingEmail model.UserEmail
	if err := db.Where("email = ?", email).First(&existingEmail).Error; err == nil {
		fmt.Printf("User with email %s already exists!\n", email)

		// Check if already admin
		var userRole model.UserRole
		if err := db.Where("user_id = ? AND role_id = ?", existingEmail.UserID, adminRole.ID).First(&userRole).Error; err == nil {
			fmt.Println("User is already an administrator!")
			os.Exit(1)
		}

		// Ask if want to grant admin role to existing user
		fmt.Printf("Do you want to grant administrator role to existing user? (y/n): ")
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))

		if response == "y" || response == "yes" {
			userRole := model.UserRole{
				UserID:    existingEmail.UserID,
				RoleID:    adminRole.ID,
				GrantedBy: existingEmail.UserID,
			}
			if err := db.Create(&userRole).Error; err != nil {
				fmt.Printf("Error granting admin role: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Administrator role granted successfully!")
			return
		}
		os.Exit(0)
	}

	// Create new admin user
	config := seed.AdminConfig{
		Email:       email,
		Password:    password,
		DisplayName: name,
	}

	if err := createAdminUser(db, config, adminRole.ID); err != nil {
		fmt.Printf("Error creating admin: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Administrator account created successfully!")
}

func listAdmins() {
	db := getDB()

	// Get admin role
	var adminRole model.Role
	if err := db.Where("name = ?", model.RoleAdmin).First(&adminRole).Error; err != nil {
		fmt.Printf("Error finding admin role: %v\n", err)
		os.Exit(1)
	}

	// Get all users with admin role
	var userRoles []model.UserRole
	if err := db.Where("role_id = ?", adminRole.ID).
		Preload("User").
		Preload("User.Profile").
		Preload("User.Emails", "is_primary = ?", true).
		Find(&userRoles).Error; err != nil {
		fmt.Printf("Error fetching admins: %v\n", err)
		os.Exit(1)
	}

	if len(userRoles) == 0 {
		fmt.Println("No administrator accounts found.")
		return
	}

	fmt.Println("\nAdministrator Accounts:")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("%-10s %-30s %-20s %-15s\n", "ID", "Email", "Display Name", "Status")
	fmt.Println(strings.Repeat("-", 80))

	for _, ur := range userRoles {
		email := ""
		if len(ur.User.Emails) > 0 {
			email = ur.User.Emails[0].Email
		}
		displayName := ""
		displayName = ur.User.Profile.DisplayName
		fmt.Printf("%-10d %-30s %-20s %-15s\n",
			ur.User.ID,
			email,
			displayName,
			ur.User.Status)
	}
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("Total: %d administrator(s)\n", len(userRoles))
}

func removeAdmin(email string) {
	db := getDB()

	// Get admin role
	var adminRole model.Role
	if err := db.Where("name = ?", model.RoleAdmin).First(&adminRole).Error; err != nil {
		fmt.Printf("Error finding admin role: %v\n", err)
		os.Exit(1)
	}

	// Find user by email
	var userEmail model.UserEmail
	if err := db.Where("email = ?", email).First(&userEmail).Error; err != nil {
		fmt.Printf("User with email %s not found!\n", email)
		os.Exit(1)
	}

	// Check if user has admin role
	var userRole model.UserRole
	if err := db.Where("user_id = ? AND role_id = ?", userEmail.UserID, adminRole.ID).First(&userRole).Error; err != nil {
		fmt.Printf("User %s is not an administrator!\n", email)
		os.Exit(1)
	}

	// Count remaining admins
	var adminCount int64
	db.Model(&model.UserRole{}).Where("role_id = ?", adminRole.ID).Count(&adminCount)
	if adminCount <= 1 {
		fmt.Println("Cannot remove the last administrator!")
		os.Exit(1)
	}

	// Confirm removal
	fmt.Printf("Are you sure you want to remove administrator role from %s? (y/n): ", email)
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))

	if response != "y" && response != "yes" {
		fmt.Println("Operation cancelled.")
		os.Exit(0)
	}

	// Remove admin role
	if err := db.Delete(&userRole).Error; err != nil {
		fmt.Printf("Error removing admin role: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Administrator role removed from %s successfully!\n", email)
}

// Helper function to create admin user (reuse seed logic)
func createAdminUser(db *gorm.DB, config seed.AdminConfig, adminRoleID uint64) error {
	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(config.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	// Start transaction
	return db.Transaction(func(tx *gorm.DB) error {
		// Create user
		user := model.User{
			PrimaryLoginType: model.LoginTypeEmail,
			Status:           model.UserStatusActive,
		}

		if err := tx.Create(&user).Error; err != nil {
			return fmt.Errorf("create user: %w", err)
		}

		// Create user profile
		profile := model.UserProfile{
			UserID:      user.ID,
			DisplayName: config.DisplayName,
			Locale:      "en_US",
		}

		if err := tx.Create(&profile).Error; err != nil {
			return fmt.Errorf("create profile: %w", err)
		}

		// Create user email
		email := model.UserEmail{
			UserID:    user.ID,
			Email:     config.Email,
			IsPrimary: true,
			VerifiedAt: sql.NullTime{
				Time:  time.Now(),
				Valid: true,
			},
		}

		if err := tx.Create(&email).Error; err != nil {
			return fmt.Errorf("create email: %w", err)
		}

		// Create user credential
		credential := model.UserCredential{
			UserID:            user.ID,
			Provider:          "email",
			ProviderAccountID: config.Email,
			PasswordHash:      string(passwordHash),
		}

		if err := tx.Create(&credential).Error; err != nil {
			return fmt.Errorf("create credential: %w", err)
		}

		// Assign admin role
		userRole := model.UserRole{
			UserID:    user.ID,
			RoleID:    adminRoleID,
			GrantedBy: user.ID, // Self-granted for initial admin
		}

		if err := tx.Create(&userRole).Error; err != nil {
			return fmt.Errorf("assign admin role: %w", err)
		}

		return nil
	})
}

// Helper functions for interactive input
func promptInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func promptPassword(prompt string) string {
	fmt.Print(prompt)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Printf("\nError reading password: %v\n", err)
		os.Exit(1)
	}
	fmt.Println()
	return string(bytePassword)
}

// resetPassword resets the password for a user
func resetPassword(email string, cmd *cobra.Command) {
	db := getDB()

	// Find user by email
	var userEmail model.UserEmail
	if err := db.Where("email = ?", email).First(&userEmail).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			fmt.Printf("User with email %s not found!\n", email)
		} else {
			fmt.Printf("Error finding user: %v\n", err)
		}
		os.Exit(1)
	}

	// Get the user
	var user model.User
	if err := db.First(&user, userEmail.UserID).Error; err != nil {
		fmt.Printf("Error loading user: %v\n", err)
		os.Exit(1)
	}

	// Get user profile for display
	var profile model.UserProfile
	if err := db.Where("user_id = ?", user.ID).First(&profile).Error; err == nil {
		fmt.Printf("\nResetting password for user:\n")
		fmt.Printf("  ID: %d\n", user.ID)
		fmt.Printf("  Email: %s\n", email)
		fmt.Printf("  Display Name: %s\n", profile.DisplayName)
		fmt.Printf("  Status: %s\n", user.Status)
		fmt.Println()
	}

	// Get new password
	newPassword, _ := cmd.Flags().GetString("password")

	// Interactive mode if password not provided
	if newPassword == "" {
		newPassword = promptPassword("Enter new password: ")
		confirmPassword := promptPassword("Confirm new password: ")
		if newPassword != confirmPassword {
			fmt.Println("Passwords do not match!")
			os.Exit(1)
		}
	}

	// Validate password length
	if len(newPassword) < 6 {
		fmt.Println("Password must be at least 6 characters long!")
		os.Exit(1)
	}

	// Confirmation prompt
	force, _ := cmd.Flags().GetBool("force")
	if !force {
		fmt.Printf("Are you sure you want to reset the password for %s? (y/n): ", email)
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))

		if response != "y" && response != "yes" {
			fmt.Println("Operation cancelled.")
			os.Exit(0)
		}
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		fmt.Printf("Error hashing password: %v\n", err)
		os.Exit(1)
	}

	// Update the credential
	var credential model.UserCredential
	if err := db.Where("user_id = ? AND provider = ?", user.ID, "email").First(&credential).Error; err != nil {
		fmt.Printf("Error finding user credential: %v\n", err)
		os.Exit(1)
	}

	// Update password
	if err := db.Model(&credential).Update("password_hash", string(hashedPassword)).Error; err != nil {
		fmt.Printf("Error updating password: %v\n", err)
		os.Exit(1)
	}

	// Clear any existing sessions for security
	if err := db.Where("user_id = ?", user.ID).Delete(&model.UserSession{}).Error; err != nil {
		fmt.Printf("Warning: Error clearing user sessions: %v\n", err)
	}

	fmt.Println("\n✅ Password reset successfully!")
	fmt.Println("The user will need to log in with the new password.")

	// Check if this is an admin
	var adminRole model.Role
	db.Where("name = ?", model.RoleAdmin).First(&adminRole)
	var userRole model.UserRole
	if db.Where("user_id = ? AND role_id = ?", user.ID, adminRole.ID).First(&userRole).Error == nil {
		fmt.Println("\n⚠️  This user is an administrator. Make sure to communicate the new password securely.")
	}
}

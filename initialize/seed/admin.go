package seed

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"paigram/internal/model"
)

// AdminConfig holds configuration for creating the default admin user.
type AdminConfig struct {
	Email       string
	Password    string
	DisplayName string
}

// CreateDefaultAdmin creates a default admin user if it doesn't exist.
// It reads admin credentials from environment variables or uses provided config.
func CreateDefaultAdmin(db *gorm.DB) error {
	// Check if admin user already exists
	var adminRole model.Role
	if err := db.Where("name = ?", model.RoleAdmin).First(&adminRole).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("admin role not found, please run seed roles first")
		}
		return fmt.Errorf("check admin role: %w", err)
	}

	// Check if any user has admin role
	var count int64
	if err := db.Model(&model.UserRole{}).Where("role_id = ?", adminRole.ID).Count(&count).Error; err != nil {
		return fmt.Errorf("check existing admins: %w", err)
	}

	if count > 0 {
		log.Printf("Admin user already exists, skipping creation")
		return nil
	}

	// Get admin credentials from environment or use defaults
	config := AdminConfig{
		Email:       getEnvOrDefault("ADMIN_EMAIL", "admin@paigram.local"),
		Password:    getEnvOrDefault("ADMIN_PASSWORD", "admin123456"),
		DisplayName: getEnvOrDefault("ADMIN_NAME", "Administrator"),
	}

	log.Printf("Creating default admin user with email: %s", config.Email)

	return createAdminUser(db, config, adminRole.ID)
}

// createAdminUser creates an admin user with the given configuration.
func createAdminUser(db *gorm.DB, config AdminConfig, adminRoleID uint64) error {
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

		log.Printf("Successfully created admin user (ID: %d) with email: %s", user.ID, config.Email)
		log.Printf("IMPORTANT: Please change the default admin password immediately!")

		return nil
	})
}

// getEnvOrDefault retrieves an environment variable or returns a default value.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

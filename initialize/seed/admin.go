package seed

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"paigram/internal/model"
)

// defaultAdminEmail is used when ADMIN_EMAIL is not provided.
const defaultAdminEmail = "admin@paigram.local"

// generatedPasswordBytes controls the entropy of auto-generated admin passwords.
// 24 random bytes => 32-character URL-safe base64 string.
const generatedPasswordBytes = 24

// AdminConfig holds configuration for creating the default admin user.
type AdminConfig struct {
	Email       string
	Password    string
	DisplayName string
}

// generateRandomPassword returns a cryptographically random URL-safe password.
// Exposed as a variable so tests can stub deterministic values if needed.
var generateRandomPassword = func() (string, error) {
	buf := make([]byte, generatedPasswordBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	// URL-safe, no padding so the secret can be copy-pasted easily.
	return strings.TrimRight(base64.URLEncoding.EncodeToString(buf), "="), nil
}

// resolveAdminConfig builds the admin config, generating the email and/or
// password when either is missing from the environment. Generated credentials
// are returned in `generated` so the caller can decide how to surface them.
type generatedFlags struct {
	email    bool
	password bool
}

func resolveAdminConfig() (AdminConfig, generatedFlags, error) {
	var flags generatedFlags

	email := os.Getenv("ADMIN_EMAIL")
	if email == "" {
		email = defaultAdminEmail
		flags.email = true
	}

	password := os.Getenv("ADMIN_PASSWORD")
	if password == "" {
		generated, err := generateRandomPassword()
		if err != nil {
			return AdminConfig{}, flags, fmt.Errorf("generate admin password: %w", err)
		}
		password = generated
		flags.password = true
	}

	cfg := AdminConfig{
		Email:       email,
		Password:    password,
		DisplayName: getEnvOrDefault("ADMIN_NAME", "Administrator"),
	}
	return cfg, flags, nil
}

// announceGeneratedCredentials prints a clearly formatted, single-shot banner
// to stdout when the bootstrap step had to invent credentials. The plaintext
// password is printed exactly once because it is not recoverable afterward.
func announceGeneratedCredentials(cfg AdminConfig, flags generatedFlags) {
	if !flags.email && !flags.password {
		return
	}

	log.Println("================================================================")
	log.Println("  Default admin user has been bootstrapped.")
	if flags.email {
		log.Printf("  Email    (auto-generated): %s", cfg.Email)
	} else {
		log.Printf("  Email    (from ADMIN_EMAIL): %s", cfg.Email)
	}
	if flags.password {
		log.Printf("  Password (auto-generated): %s", cfg.Password)
		log.Println("  This password will NOT be shown again. Save it now and")
		log.Println("  rotate it via the admin UI as soon as possible.")
	}
	log.Println("================================================================")
}

// CreateDefaultAdmin creates a default admin user if it doesn't exist.
// It reads admin credentials from environment variables when available; any
// missing value (email and/or password) is filled in with a safe default or a
// freshly generated random secret, and the resulting credentials are logged
// once so an operator can capture them on first boot.
func CreateDefaultAdmin(db *gorm.DB) error {
	// Check if admin user already exists
	var adminRole model.Role
	if err := db.Where("name = ?", model.RoleAdmin).First(&adminRole).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("admin role not found, please run seed roles first")
		}
		return fmt.Errorf("check admin role: %w", err)
	}

	// Check if any active user has the admin role
	var count int64
	if err := db.Table("user_roles").
		Joins("JOIN users ON users.id = user_roles.user_id").
		Where("user_roles.role_id = ? AND users.status = ?", adminRole.ID, model.UserStatusActive).
		Count(&count).Error; err != nil {
		return fmt.Errorf("check existing admins: %w", err)
	}

	if count > 0 {
		log.Printf("Admin user already exists, skipping creation")
		return nil
	}

	cfg, flags, err := resolveAdminConfig()
	if err != nil {
		return err
	}

	log.Printf("Creating default admin user with email: %s", cfg.Email)

	if err := createAdminUser(db, cfg, adminRole.ID); err != nil {
		return err
	}

	announceGeneratedCredentials(cfg, flags)
	return nil
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

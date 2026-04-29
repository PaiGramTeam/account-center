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

// defaultAdminEmail is used when ADMIN_EMAIL is not provided.
const defaultAdminEmail = "admin@paigram.local"

// DefaultBcryptCost matches the OWASP-recommended cost the rest of the
// system uses when an explicit Config is unavailable. Callers that have
// access to *config.Config should pass cfg.GetBcryptCost() instead.
const DefaultBcryptCost = 12

// AdminConfig holds configuration for creating the default admin user.
type AdminConfig struct {
	Email       string
	Password    string
	DisplayName string
}

// resolveAdminConfig builds the admin config from environment variables.
//
// V6: ADMIN_PASSWORD is mandatory. We deliberately refuse to auto-generate
// a password — anything we did with a generated value (logging it,
// writing it to a file, printing only to a TTY) would either leak via log
// aggregators or break docker-exec / non-TTY scenarios. Failing closed
// makes the operator decide once and the seed step never fingerprints
// the value into rotated storage.
func resolveAdminConfig() (AdminConfig, error) {
	email := os.Getenv("ADMIN_EMAIL")
	if email == "" {
		email = defaultAdminEmail
	}

	password := os.Getenv("ADMIN_PASSWORD")
	if password == "" {
		return AdminConfig{}, errors.New(
			"ADMIN_PASSWORD must be set; refusing to auto-generate a password " +
				"(would leak via logs or files). Set ADMIN_PASSWORD to a strong " +
				"value (>=8 chars) and re-run seed.")
	}

	displayName := os.Getenv("ADMIN_NAME")
	if displayName == "" {
		displayName = "Administrator"
	}

	return AdminConfig{
		Email:       email,
		Password:    password,
		DisplayName: displayName,
	}, nil
}

// CreateDefaultAdmin creates a default admin user if it doesn't exist.
//
// Credentials come exclusively from environment variables:
//
//	ADMIN_EMAIL    - optional, defaults to admin@paigram.local
//	ADMIN_PASSWORD - REQUIRED; the call fails closed if unset (V6)
//	ADMIN_NAME     - optional, defaults to "Administrator"
//
// bcryptCost should be the operator-configured cost (typically
// cfg.GetBcryptCost()). A value below 10 is bumped to DefaultBcryptCost.
func CreateDefaultAdmin(db *gorm.DB, bcryptCost int) error {
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

	cfg, err := resolveAdminConfig()
	if err != nil {
		return err
	}

	log.Printf("Creating default admin user with email: %s", cfg.Email)

	if err := createAdminUser(db, cfg, adminRole.ID, bcryptCost); err != nil {
		return err
	}

	log.Println("================================================================")
	log.Println("  Default admin user has been bootstrapped.")
	log.Printf("  Email: %s", cfg.Email)
	log.Println("  Password: (set via ADMIN_PASSWORD environment variable)")
	log.Println("  Rotate the password via the admin UI as soon as possible.")
	log.Println("================================================================")
	return nil
}

// resolveBcryptCost clamps the cost into the safe [10,14] range.
func resolveBcryptCost(cost int) int {
	if cost < 10 {
		return DefaultBcryptCost
	}
	if cost > 14 {
		return 14
	}
	return cost
}

// createAdminUser creates an admin user with the given configuration.
func createAdminUser(db *gorm.DB, config AdminConfig, adminRoleID uint64, bcryptCost int) error {
	// Hash password with the operator-configured cost (V8).
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(config.Password), resolveBcryptCost(bcryptCost))
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

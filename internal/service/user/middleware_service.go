package user

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"paigram/internal/model"
)

var ErrTwoFactorNotEnabled = errors.New("2FA not enabled for user")

// MiddlewareService provides data access methods for middleware layer.
// This service encapsulates database queries needed by various middleware,
// maintaining the strict layered architecture (Middleware → Service → Model).
type MiddlewareService struct {
	db *gorm.DB
}

// GetUserRoles retrieves all role IDs for a given user.
// Used by permission middleware to check user's roles.
func (s *MiddlewareService) GetUserRoles(userID uint64) ([]uint64, error) {
	var userRoles []model.UserRole
	if err := s.db.Where("user_id = ?", userID).Find(&userRoles).Error; err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	roleIDs := make([]uint64, len(userRoles))
	for i, ur := range userRoles {
		roleIDs[i] = ur.RoleID
	}
	return roleIDs, nil
}

// HasAnyRole checks if a user has any of the specified role names.
// Used by RequireRoleMiddleware to validate role membership.
func (s *MiddlewareService) HasAnyRole(userID uint64, roleNames []string) (bool, error) {
	if len(roleNames) == 0 {
		return false, nil
	}

	var count int64
	err := s.db.Model(&model.UserRole{}).
		Joins("JOIN roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id = ? AND roles.name IN ?", userID, roleNames).
		Limit(1).
		Count(&count).Error

	if err != nil {
		return false, fmt.Errorf("failed to check roles: %w", err)
	}

	return count > 0, nil
}

// GetSessionByAccessToken retrieves a session by access token hash.
// Used by auth middleware to validate access tokens.
func (s *MiddlewareService) GetSessionByAccessToken(accessTokenHash string) (*model.UserSession, error) {
	var session model.UserSession
	if err := s.db.Where("access_token_hash = ?", accessTokenHash).First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // Return nil without error for not found
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	return &session, nil
}

// GetUserByID retrieves a user by ID (optimized for middleware - no preloads).
// Used by auth middleware to verify user existence and status.
func (s *MiddlewareService) GetUserByID(userID uint64) (*model.User, error) {
	var user model.User
	if err := s.db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // Return nil without error for not found
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

// GetTwoFactorSecret retrieves the 2FA secret for a user.
// Used by 2FA middleware to validate TOTP codes.
func (s *MiddlewareService) GetTwoFactorSecret(userID uint64) (string, error) {
	var twoFactor model.UserTwoFactor
	if err := s.db.Where("user_id = ?", userID).First(&twoFactor).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("%w", ErrTwoFactorNotEnabled)
		}
		return "", fmt.Errorf("failed to get 2FA secret: %w", err)
	}
	return twoFactor.Secret, nil
}

// GetSessionByID retrieves a session by its ID.
// Used by freshness and session validation middleware.
func (s *MiddlewareService) GetSessionByID(sessionID uint64) (*model.UserSession, error) {
	var session model.UserSession
	if err := s.db.First(&session, sessionID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // Return nil without error for not found
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	return &session, nil
}

// UpdateUserLastLogin updates the last_login_at timestamp for a user.
// Used by session middleware to track login activity.
func (s *MiddlewareService) UpdateUserLastLogin(userID uint64, lastLogin time.Time) error {
	result := s.db.Model(&model.User{}).
		Where("id = ?", userID).
		Update("last_login_at", sql.NullTime{Time: lastLogin, Valid: true})

	if result.Error != nil {
		return fmt.Errorf("failed to update last login: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("user %d not found", userID)
	}
	return nil
}

// UpdateSessionExpiry refreshes session expiry timestamps and update time.
// Used by auth middleware to restore sliding session refresh semantics.
func (s *MiddlewareService) UpdateSessionExpiry(sessionID uint64, accessExpiry, refreshExpiry, updatedAt time.Time) error {
	result := s.db.Model(&model.UserSession{}).
		Where("id = ?", sessionID).
		Updates(map[string]any{
			"access_expiry":  accessExpiry,
			"refresh_expiry": refreshExpiry,
			"updated_at":     updatedAt,
		})

	if result.Error != nil {
		return fmt.Errorf("failed to update session expiry: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("session %d not found", sessionID)
	}
	return nil
}

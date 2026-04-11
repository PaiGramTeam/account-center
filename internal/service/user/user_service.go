package user

import (
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"paigram/internal/model"
)

// UserService handles user business logic.
type UserService struct {
	db *gorm.DB
}

// ListUsersParams defines parameters for listing users.
type ListUsersParams struct {
	Page     int
	PageSize int
	SortBy   string
	Order    string
	Status   string
	Search   string
}

// ListUsersResult contains paginated user list results.
type ListUsersResult struct {
	Users []model.User
	Total int64
}

// ListUsers retrieves users with filtering and pagination.
func (s *UserService) ListUsers(params ListUsersParams) (*ListUsersResult, error) {
	// Validate pagination
	if params.Page < 1 {
		params.Page = 1
	}
	if params.PageSize < 1 {
		params.PageSize = 20
	}
	if params.PageSize > 100 {
		params.PageSize = 100
	}

	// Validate sort field
	allowedSortFields := map[string]bool{
		"id":            true,
		"created_at":    true,
		"last_login_at": true,
	}
	if !allowedSortFields[params.SortBy] {
		params.SortBy = "created_at"
	}

	// Validate order
	if params.Order != "asc" && params.Order != "desc" {
		params.Order = "desc"
	}

	// Build query
	query := s.db.Model(&model.User{})

	// Apply filters
	if params.Status != "" {
		query = query.Where("status = ?", params.Status)
	}

	if params.Search != "" {
		search := "%" + strings.ToLower(params.Search) + "%"
		query = query.Joins("LEFT JOIN user_profiles ON users.id = user_profiles.user_id").
			Joins("LEFT JOIN user_emails ON user_emails.user_id = users.id AND user_emails.is_primary = ?", true).
			Where("LOWER(user_profiles.display_name) LIKE ? OR LOWER(user_emails.email) LIKE ?", search, search)
	}

	// Count total
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("failed to count users: %w", err)
	}

	// Apply pagination and sorting
	offset := (params.Page - 1) * params.PageSize
	orderClause := fmt.Sprintf("%s %s", params.SortBy, params.Order)

	var users []model.User
	if err := query.Preload("Profile").
		Order(orderClause).
		Limit(params.PageSize).
		Offset(offset).
		Find(&users).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch users: %w", err)
	}

	return &ListUsersResult{
		Users: users,
		Total: total,
	}, nil
}

// GetUserByID retrieves a user by ID.
func (s *UserService) GetUserByID(userID uint64) (*model.User, error) {
	var user model.User
	if err := s.db.Preload("Profile").First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to load user: %w", err)
	}
	return &user, nil
}

// CreateUserParams defines parameters for creating a user.
type CreateUserParams struct {
	PrimaryLoginType model.LoginType
	DisplayName      string
	AvatarURL        string
	Bio              string
}

// CreateUser creates a new user with profile.
func (s *UserService) CreateUser(params CreateUserParams) (*model.User, error) {
	// Validate required fields
	if params.DisplayName == "" {
		return nil, errors.New("display_name is required")
	}

	user := &model.User{
		PrimaryLoginType: params.PrimaryLoginType,
		Status:           model.UserStatusPending,
		Profile: model.UserProfile{
			DisplayName: params.DisplayName,
			AvatarURL:   params.AvatarURL,
			Bio:         params.Bio,
		},
	}

	if err := s.db.Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// UpdateUserParams defines parameters for updating a user.
type UpdateUserParams struct {
	DisplayName *string
	AvatarURL   *string
	Bio         *string
}

// UpdateUser updates user profile fields.
func (s *UserService) UpdateUser(userID uint64, params UpdateUserParams) (*model.User, error) {
	var user model.User
	if err := s.db.Preload("Profile").First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("failed to load user: %w", err)
	}

	// Update fields
	updates := make(map[string]interface{})
	if params.DisplayName != nil {
		updates["display_name"] = *params.DisplayName
	}
	if params.AvatarURL != nil {
		updates["avatar_url"] = *params.AvatarURL
	}
	if params.Bio != nil {
		updates["bio"] = *params.Bio
	}

	if err := s.db.Model(&user.Profile).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("failed to update user profile: %w", err)
	}

	return &user, nil
}

// DeleteUser soft deletes a user.
func (s *UserService) DeleteUser(userID uint64) error {
	result := s.db.Delete(&model.User{}, userID)
	if result.Error != nil {
		return fmt.Errorf("failed to delete user: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return errors.New("user not found")
	}
	return nil
}

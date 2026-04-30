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

// allowedListUsersOrderClauses maps validated (sort_by, order) pairs to
// constant SQL fragments. Keeping the values as compile-time constants is
// what guarantees that user input never participates in the rendered ORDER
// BY clause and is what tools like CodeQL look for to clear SQL-injection
// taint.
var allowedListUsersOrderClauses = map[string]string{
	"id|asc":             "id ASC",
	"id|desc":            "id DESC",
	"created_at|asc":     "created_at ASC",
	"created_at|desc":    "created_at DESC",
	"last_login_at|asc":  "last_login_at ASC",
	"last_login_at|desc": "last_login_at DESC",
}

// resolveListUsersOrderClause picks the safe ORDER BY fragment for the given
// user-provided sort field and direction. Unknown or empty values fall back
// to the default `created_at DESC`.
func resolveListUsersOrderClause(sortBy, order string) string {
	sortKey := strings.TrimSpace(sortBy)
	if sortKey == "" {
		sortKey = "created_at"
	}
	orderKey := strings.ToLower(strings.TrimSpace(order))
	if orderKey != "asc" && orderKey != "desc" {
		orderKey = "desc"
	}
	if clause, ok := allowedListUsersOrderClauses[sortKey+"|"+orderKey]; ok {
		return clause
	}
	return "created_at DESC"
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

	orderClause := resolveListUsersOrderClause(params.SortBy, params.Order)

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

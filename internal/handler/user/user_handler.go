package user

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"paigram/internal/handler/shared"
	"paigram/internal/middleware"
	"paigram/internal/model"
	"paigram/internal/response"
)

// Handler exposes REST handlers for user resources.
type Handler struct {
	db *gorm.DB
}

// NewHandler constructs a handler with the provided database.
func NewHandler(db *gorm.DB) *Handler {
	return &Handler{db: db}
}

// RegisterRoutes binds user routes to the router group.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.GET("", h.ListUsers)
	rg.POST("", h.CreateUser)
	rg.GET("/:id", h.GetUser)
	rg.PATCH("/:id", h.UpdateUser)
	rg.DELETE("/:id", h.DeleteUser)
	rg.PATCH("/:id/status", h.UpdateUserStatus)
	rg.POST("/:id/reset-password", h.ResetUserPassword)
	rg.GET("/:id/audit-logs", h.GetAuditLogs)
	rg.GET("/:id/roles", h.GetUserRoles)
	rg.GET("/:id/permissions", h.GetUserPermissions)
}

// swagger:route GET /api/v1/users users listUsers
//
// 列出所有用户及其基础信息。
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: userListResponse
//	400: errorResponse
//	500: errorResponse
//
// ListUsers returns all users with basic profile metadata.
func (h *Handler) ListUsers(c *gin.Context) {
	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	sortBy := c.DefaultQuery("sort_by", "created_at")
	order := c.DefaultQuery("order", "desc")
	status := c.Query("status")
	search := strings.TrimSpace(c.Query("search"))

	// Validate sort field
	allowedSortFields := map[string]bool{
		"id":            true,
		"created_at":    true,
		"last_login_at": true,
	}
	if !allowedSortFields[sortBy] {
		sortBy = "created_at"
	}

	// Validate order
	if order != "asc" && order != "desc" {
		order = "desc"
	}

	// Build query
	query := h.db.Model(&model.User{})

	// Apply filters
	if status != "" {
		query = query.Where("status = ?", status)
	}

	if search != "" {
		query = query.Joins("LEFT JOIN user_profiles ON user_profiles.user_id = users.id").
			Joins("LEFT JOIN user_emails ON user_emails.user_id = users.id AND user_emails.is_primary = ?", true).
			Where("user_emails.email LIKE ? OR user_profiles.display_name LIKE ?",
				"%"+search+"%", "%"+search+"%")
	}

	// Count total
	var total int64
	if err := query.Count(&total).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to count users", nil)
		return
	}

	// Apply pagination
	offset := (page - 1) * pageSize
	var users []model.User

	orderClause := sortBy + " " + strings.ToUpper(order)
	if err := query.Preload("Profile").Preload("Emails").
		Order(orderClause).
		Limit(pageSize).
		Offset(offset).
		Find(&users).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to list users", nil)
		return
	}

	results := make([]UserListItem, 0, len(users))
	for _, user := range users {
		results = append(results, UserListItem{
			ID:               user.ID,
			Status:           user.Status,
			PrimaryLoginType: user.PrimaryLoginType,
			DisplayName:      user.Profile.DisplayName,
			PrimaryEmail:     primaryEmail(user.Emails),
			LastLoginAt:      shared.NullTimePtr(user.LastLoginAt),
			CreatedAt:        user.CreatedAt,
		})
	}

	response.SuccessWithPagination(c, results, total, page, pageSize)
}

// swagger:route GET /api/v1/users/{id} users getUser
//
// 查看指定用户的详细信息。
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: userDetailResponse
//	400: errorResponse
//	404: errorResponse
//	500: errorResponse
//
// GetUser retrieves full details for a user by id.
func (h *Handler) GetUser(c *gin.Context) {
	id, err := strconv.ParseUint(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}

	var user model.User
	if err := h.db.Preload("Profile").Preload("Emails").Preload("Sessions").First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFound(c, "user not found")
			return
		}
		response.InternalServerError(c, "failed to load user")
		return
	}

	emails := make([]UserEmailPayload, 0, len(user.Emails))
	for _, email := range user.Emails {
		emails = append(emails, UserEmailPayload{
			Email:      email.Email,
			IsPrimary:  email.IsPrimary,
			VerifiedAt: shared.NullTimePtr(email.VerifiedAt),
		})
	}

	userData := UserDetail{
		ID:               user.ID,
		Status:           user.Status,
		PrimaryLoginType: user.PrimaryLoginType,
		DisplayName:      user.Profile.DisplayName,
		AvatarURL:        user.Profile.AvatarURL,
		Bio:              user.Profile.Bio,
		Locale:           user.Profile.Locale,
		PrimaryEmail:     primaryEmail(user.Emails),
		Emails:           emails,
		LastLoginAt:      shared.NullTimePtr(user.LastLoginAt),
		CreatedAt:        user.CreatedAt,
		UpdatedAt:        user.UpdatedAt,
	}

	response.Success(c, userData)
}

func primaryEmail(emails []model.UserEmail) string {
	for _, email := range emails {
		if email.IsPrimary {
			return email.Email
		}
	}
	if len(emails) > 0 {
		return emails[0].Email
	}
	return ""
}

// SessionResponse represents a user session in management APIs.
type SessionResponse struct {
	ID            uint64     `json:"id"`
	DeviceID      string     `json:"device_id,omitempty"`
	DeviceName    string     `json:"device_name,omitempty"`
	DeviceType    string     `json:"device_type,omitempty"`
	IP            string     `json:"ip,omitempty"`
	Location      string     `json:"location,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	LastActiveAt  *time.Time `json:"last_active_at,omitempty"`
	AccessExpiry  time.Time  `json:"access_expiry"`
	RefreshExpiry time.Time  `json:"refresh_expiry"`
	IsCurrent     bool       `json:"is_current"`
}

// SecuritySummary captures a user's security posture for management UIs.
type SecuritySummary struct {
	UserID                 uint64     `json:"user_id"`
	TwoFactorEnabled       bool       `json:"two_factor_enabled"`
	ActiveSessionCount     int64      `json:"active_session_count"`
	DeviceCount            int64      `json:"device_count"`
	FailedLoginsLast30Days int64      `json:"failed_logins_last_30_days"`
	LastLoginAt            *time.Time `json:"last_login_at,omitempty"`
	LastLoginIP            string     `json:"last_login_ip,omitempty"`
	LastLoginDevice        string     `json:"last_login_device,omitempty"`
	LastLoginLocation      string     `json:"last_login_location,omitempty"`
}

func hashBearerToken(token string) string {
	if token == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", hash[:])
}

func buildDeviceID(userAgent, clientIP string) string {
	if userAgent == "" && clientIP == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(userAgent + clientIP))
	return base64.URLEncoding.EncodeToString(hash[:])[:22]
}

// GetUserSessions returns a user's active sessions with pagination.
func (h *Handler) GetUserSessions(c *gin.Context) {
	userID, err := strconv.ParseUint(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidUserID, "invalid user id", nil)
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	var total int64
	query := h.db.Model(&model.UserSession{}).Where("user_id = ? AND revoked_at IS NULL", userID)
	if err := query.Count(&total).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to count user sessions", nil)
		return
	}

	var sessions []model.UserSession
	offset := (page - 1) * pageSize
	if err := query.Order("created_at DESC").Limit(pageSize).Offset(offset).Find(&sessions).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to fetch user sessions", nil)
		return
	}

	var devices []model.UserDevice
	deviceMap := make(map[string]model.UserDevice, len(devices))
	if err := h.db.Where("user_id = ?", userID).Find(&devices).Error; err == nil {
		for _, device := range devices {
			deviceMap[device.DeviceID] = device
		}
	}

	currentUserID, _ := middleware.GetUserID(c)
	authHeader := c.GetHeader("Authorization")
	currentTokenHash := ""
	if len(authHeader) > 7 && strings.HasPrefix(authHeader, "Bearer ") && currentUserID == userID {
		currentTokenHash = hashBearerToken(authHeader[7:])
	}

	result := make([]SessionResponse, 0, len(sessions))
	for _, session := range sessions {
		item := SessionResponse{
			ID:            session.ID,
			IP:            session.ClientIP,
			CreatedAt:     session.CreatedAt,
			AccessExpiry:  session.AccessExpiry,
			RefreshExpiry: session.RefreshExpiry,
			IsCurrent:     session.AccessTokenHash == currentTokenHash && currentTokenHash != "",
		}

		deviceID := buildDeviceID(session.UserAgent, session.ClientIP)
		if device, ok := deviceMap[deviceID]; ok {
			item.DeviceID = device.DeviceID
			item.DeviceName = device.DeviceName
			item.DeviceType = device.DeviceType
			item.Location = device.Location
			lastActive := device.LastActiveAt
			item.LastActiveAt = &lastActive
		}

		result = append(result, item)
	}

	response.SuccessWithPagination(c, result, total, page, pageSize)
}

// RevokeUserSession revokes a specific user session.
func (h *Handler) RevokeUserSession(c *gin.Context) {
	userID, err := strconv.ParseUint(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidUserID, "invalid user id", nil)
		return
	}

	sessionID, err := strconv.ParseUint(strings.TrimSpace(c.Param("sessionId")), 10, 64)
	if err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidInput, "invalid session id", nil)
		return
	}

	var session model.UserSession
	if err := h.db.Where("id = ? AND user_id = ?", sessionID, userID).First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFoundWithCode(c, response.ErrCodeUserNotFound, "session not found", nil)
			return
		}
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to load session", nil)
		return
	}

	if session.RevokedAt.Valid {
		response.Success(c, gin.H{"message": "session already revoked"})
		return
	}

	actorID, _ := middleware.GetUserID(c)
	reason := "revoked by admin"
	if actorID == userID {
		reason = "revoked by user"
	}

	now := time.Now().UTC()
	updates := map[string]any{
		"revoked_at":     sql.NullTime{Time: now, Valid: true},
		"revoked_reason": reason,
	}
	if err := h.db.Model(&session).Updates(updates).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to revoke session", nil)
		return
	}

	response.Success(c, gin.H{"message": "session revoked successfully"})
}

// GetSecuritySummary returns security-related summary data for a user.
func (h *Handler) GetSecuritySummary(c *gin.Context) {
	userID, err := strconv.ParseUint(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidUserID, "invalid user id", nil)
		return
	}

	summary := SecuritySummary{UserID: userID}

	var twoFactor model.UserTwoFactor
	err = h.db.Where("user_id = ?", userID).First(&twoFactor).Error
	if err == nil {
		summary.TwoFactorEnabled = true
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to load 2fa status", nil)
		return
	}

	if err := h.db.Model(&model.UserSession{}).Where("user_id = ? AND revoked_at IS NULL", userID).Count(&summary.ActiveSessionCount).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to count active sessions", nil)
		return
	}

	if err := h.db.Model(&model.UserDevice{}).Where("user_id = ?", userID).Count(&summary.DeviceCount).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to count user devices", nil)
		return
	}

	since := time.Now().UTC().AddDate(0, 0, -30)
	if err := h.db.Model(&model.LoginLog{}).Where("user_id = ? AND status = ? AND created_at >= ?", userID, "failed", since).Count(&summary.FailedLoginsLast30Days).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to count failed logins", nil)
		return
	}

	var lastLogin model.LoginLog
	err = h.db.Where("user_id = ? AND status = ?", userID, "success").Order("created_at DESC").First(&lastLogin).Error
	if err == nil {
		summary.LastLoginAt = &lastLogin.CreatedAt
		summary.LastLoginIP = lastLogin.IP
		summary.LastLoginDevice = lastLogin.Device
		summary.LastLoginLocation = lastLogin.Location
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to load latest login", nil)
		return
	}

	response.Success(c, summary)
}

// swagger:route POST /api/v1/users users createUser
//
// 创建新用户（管理员功能）。
//
// Produces:
//   - application/json
//
// Responses:
//
//	201: createUserResponse
//	400: errorResponse
//	409: errorResponse
//	500: errorResponse
//
// CreateUser creates a new user (admin function).
func (h *Handler) CreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidInput, "invalid request body", map[string]string{
			"error": err.Error(),
		})
		return
	}

	// Validate required fields
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		response.BadRequestWithCode(c, response.ErrCodeInvalidEmail, "email is required", nil)
		return
	}

	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		response.BadRequestWithCode(c, response.ErrCodeInvalidDisplayName, "display name is required", nil)
		return
	}

	password := req.Password
	if password == "" {
		response.BadRequestWithCode(c, response.ErrCodeInvalidPassword, "password is required", nil)
		return
	}
	if len(password) < 8 || len(password) > 72 {
		response.BadRequestWithCode(c, response.ErrCodePasswordTooWeak, "password must be between 8 and 72 characters", nil)
		return
	}

	// Check if email already exists
	var existingEmail model.UserEmail
	if err := h.db.Where("email = ?", email).First(&existingEmail).Error; err == nil {
		response.ConflictWithCode(c, response.ErrCodeEmailAlreadyInUse, "email already in use", map[string]string{
			"email": email,
		})
		return
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to check email uniqueness", nil)
		return
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeInternalError, "failed to hash password", nil)
		return
	}

	// Default values
	status := model.UserStatusActive
	if req.Status != "" {
		status = model.UserStatus(req.Status)
		// Validate status
		if status != model.UserStatusActive && status != model.UserStatusPending &&
			status != model.UserStatusSuspended && status != model.UserStatusDeleted {
			response.BadRequestWithCode(c, response.ErrCodeInvalidUserStatus, "invalid user status", map[string]string{
				"status":  req.Status,
				"allowed": "active, pending, suspended, deleted",
			})
			return
		}
	}

	locale := req.Locale
	if locale == "" {
		locale = "en_US"
	}

	// Create user in transaction
	var user model.User
	err = h.db.Transaction(func(tx *gorm.DB) error {
		user = model.User{
			PrimaryLoginType: model.LoginTypeEmail,
			Status:           status,
		}

		if err := tx.Create(&user).Error; err != nil {
			return err
		}

		profile := model.UserProfile{
			UserID:      user.ID,
			DisplayName: displayName,
			Locale:      locale,
		}
		if err := tx.Create(&profile).Error; err != nil {
			return err
		}

		credential := model.UserCredential{
			UserID:            user.ID,
			Provider:          string(model.LoginTypeEmail),
			ProviderAccountID: email,
			PasswordHash:      string(passwordHash),
		}
		if err := tx.Create(&credential).Error; err != nil {
			return err
		}

		emailRecord := model.UserEmail{
			UserID:    user.ID,
			Email:     email,
			IsPrimary: true,
		}
		if err := tx.Create(&emailRecord).Error; err != nil {
			return err
		}

		// Load created user with associations
		return tx.Preload("Profile").Preload("Emails").First(&user, user.ID).Error
	})

	if err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to create user", nil)
		return
	}

	emails := make([]UserEmailPayload, 0, len(user.Emails))
	for _, email := range user.Emails {
		emails = append(emails, UserEmailPayload{
			Email:      email.Email,
			IsPrimary:  email.IsPrimary,
			VerifiedAt: shared.NullTimePtr(email.VerifiedAt),
		})
	}

	userData := UserDetail{
		ID:               user.ID,
		Status:           user.Status,
		PrimaryLoginType: user.PrimaryLoginType,
		DisplayName:      user.Profile.DisplayName,
		AvatarURL:        user.Profile.AvatarURL,
		Bio:              user.Profile.Bio,
		Locale:           user.Profile.Locale,
		PrimaryEmail:     primaryEmail(user.Emails),
		Emails:           emails,
		LastLoginAt:      shared.NullTimePtr(user.LastLoginAt),
		CreatedAt:        user.CreatedAt,
		UpdatedAt:        user.UpdatedAt,
	}

	response.Created(c, userData)
}

// swagger:route PATCH /api/v1/users/{id} users updateUser
//
// 更新用户信息（管理员功能）。
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: updateUserResponse
//	400: errorResponse
//	404: errorResponse
//	500: errorResponse
//
// UpdateUser updates user information (admin function).
func (h *Handler) UpdateUser(c *gin.Context) {
	id, err := strconv.ParseUint(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidUserID, "invalid user id", nil)
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidInput, "invalid request body", map[string]string{
			"error": err.Error(),
		})
		return
	}

	// Check if user exists
	var user model.User
	if err := h.db.Preload("Profile").First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFoundWithCode(c, response.ErrCodeUserNotFound, "user not found", nil)
			return
		}
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to load user", nil)
		return
	}

	// Update user in transaction
	err = h.db.Transaction(func(tx *gorm.DB) error {
		// Update user status if provided
		if req.Status != "" {
			status := model.UserStatus(req.Status)
			// Validate status
			if status != model.UserStatusActive && status != model.UserStatusPending &&
				status != model.UserStatusSuspended && status != model.UserStatusDeleted {
				return errors.New("invalid user status")
			}
			if err := tx.Model(&user).Update("status", status).Error; err != nil {
				return err
			}
		}

		// Update profile if display name provided
		if req.DisplayName != "" {
			if err := tx.Model(&model.UserProfile{}).
				Where("user_id = ?", user.ID).
				Update("display_name", strings.TrimSpace(req.DisplayName)).Error; err != nil {
				return err
			}
		}

		// Update roles if provided
		if len(req.Roles) > 0 {
			// Verify all roles exist
			var roles []model.Role
			if err := tx.Where("name IN ?", req.Roles).Find(&roles).Error; err != nil {
				return err
			}
			if len(roles) != len(req.Roles) {
				return errors.New("one or more roles not found")
			}

			// Delete existing role assignments
			if err := tx.Where("user_id = ?", user.ID).Delete(&model.UserRole{}).Error; err != nil {
				return err
			}

			// Create new role assignments
			for _, role := range roles {
				userRole := model.UserRole{
					UserID: user.ID,
					RoleID: role.ID,
					// GrantedBy should be set from the current user context
				}
				if err := tx.Create(&userRole).Error; err != nil {
					return err
				}
			}
		}

		// Reload user with associations
		return tx.Preload("Profile").Preload("Emails").First(&user, id).Error
	})

	if err != nil {
		if err.Error() == "invalid user status" {
			response.BadRequestWithCode(c, response.ErrCodeInvalidUserStatus, "invalid user status", map[string]string{
				"status":  req.Status,
				"allowed": "active, pending, suspended, deleted",
			})
			return
		}
		if err.Error() == "one or more roles not found" {
			response.BadRequestWithCode(c, response.ErrCodeRoleNotFound, "one or more roles not found", map[string]string{
				"roles": strings.Join(req.Roles, ", "),
			})
			return
		}
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to update user", nil)
		return
	}

	emails := make([]UserEmailPayload, 0, len(user.Emails))
	for _, email := range user.Emails {
		emails = append(emails, UserEmailPayload{
			Email:      email.Email,
			IsPrimary:  email.IsPrimary,
			VerifiedAt: shared.NullTimePtr(email.VerifiedAt),
		})
	}

	userData := UserDetail{
		ID:               user.ID,
		Status:           user.Status,
		PrimaryLoginType: user.PrimaryLoginType,
		DisplayName:      user.Profile.DisplayName,
		AvatarURL:        user.Profile.AvatarURL,
		Bio:              user.Profile.Bio,
		Locale:           user.Profile.Locale,
		PrimaryEmail:     primaryEmail(user.Emails),
		Emails:           emails,
		LastLoginAt:      shared.NullTimePtr(user.LastLoginAt),
		CreatedAt:        user.CreatedAt,
		UpdatedAt:        user.UpdatedAt,
	}

	response.Success(c, userData)
}

// swagger:route DELETE /api/v1/users/{id} users deleteUser
//
// 删除用户（管理员功能）。
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: deleteUserResponse
//	400: errorResponse
//	404: errorResponse
//	500: errorResponse
//
// DeleteUser deletes a user (admin function).
func (h *Handler) DeleteUser(c *gin.Context) {
	id, err := strconv.ParseUint(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidUserID, "invalid user id", nil)
		return
	}

	hardDelete := c.Query("hard_delete") == "true"

	// Check if user exists
	var user model.User
	if err := h.db.First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFoundWithCode(c, response.ErrCodeUserNotFound, "user not found", nil)
			return
		}
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to load user", nil)
		return
	}

	// Delete user
	var deleteErr error
	if hardDelete {
		// Permanently delete
		deleteErr = h.db.Unscoped().Delete(&user).Error
	} else {
		// Soft delete
		deleteErr = h.db.Delete(&user).Error
	}

	if deleteErr != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to delete user", nil)
		return
	}

	response.Success(c, gin.H{
		"message": "user deleted successfully",
	})
}

// swagger:route PATCH /api/v1/users/{id}/status users updateUserStatus
//
// 更新用户状态（管理员功能）。
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: updateUserStatusResponse
//	400: errorResponse
//	404: errorResponse
//	500: errorResponse
//
// UpdateUserStatus updates user status (admin function).
func (h *Handler) UpdateUserStatus(c *gin.Context) {
	id, err := strconv.ParseUint(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidUserID, "invalid user id", nil)
		return
	}

	var req UpdateUserStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidInput, "invalid request body", map[string]string{
			"error": err.Error(),
		})
		return
	}

	// Validate status
	status := model.UserStatus(req.Status)
	if status != model.UserStatusActive && status != model.UserStatusPending &&
		status != model.UserStatusSuspended && status != model.UserStatusDeleted {
		response.BadRequestWithCode(c, response.ErrCodeInvalidUserStatus, "invalid user status", map[string]string{
			"status":  req.Status,
			"allowed": "active, pending, suspended, deleted",
		})
		return
	}

	// Check if user exists
	var user model.User
	if err := h.db.First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFoundWithCode(c, response.ErrCodeUserNotFound, "user not found", nil)
			return
		}
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to load user", nil)
		return
	}

	// Update status
	if err := h.db.Model(&user).Update("status", status).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to update user status", nil)
		return
	}

	response.Success(c, gin.H{
		"message": "user status updated successfully",
		"status":  status,
	})
}

// swagger:route POST /api/v1/users/{id}/reset-password users resetUserPassword
//
// 重置用户密码（管理员功能）。
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: resetPasswordResponse
//	400: errorResponse
//	404: errorResponse
//	500: errorResponse
//
// ResetUserPassword resets user password (admin function).
func (h *Handler) ResetUserPassword(c *gin.Context) {
	id, err := strconv.ParseUint(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidUserID, "invalid user id", nil)
		return
	}

	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidInput, "invalid request body", map[string]string{
			"error": err.Error(),
		})
		return
	}

	// Validate password
	password := strings.TrimSpace(req.NewPassword)
	if password == "" {
		response.BadRequestWithCode(c, response.ErrCodeInvalidPassword, "password is required", nil)
		return
	}
	if len(password) < 8 || len(password) > 72 {
		response.BadRequestWithCode(c, response.ErrCodePasswordTooWeak, "password must be between 8 and 72 characters", nil)
		return
	}

	// Check if user exists
	var user model.User
	if err := h.db.First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFoundWithCode(c, response.ErrCodeUserNotFound, "user not found", nil)
			return
		}
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to load user", nil)
		return
	}

	// Hash new password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeInternalError, "failed to hash password", nil)
		return
	}

	// Update password in user_credentials table
	if err := h.db.Model(&model.UserCredential{}).
		Where("user_id = ? AND provider = ?", user.ID, model.LoginTypeEmail).
		Update("password_hash", string(passwordHash)).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to update password", nil)
		return
	}

	// Optionally: invalidate all user sessions to force re-login
	if req.InvalidateSessions {
		// Delete all active sessions for this user
		if err := h.db.Where("user_id = ?", user.ID).Delete(&model.UserSession{}).Error; err != nil {
			// Log error but don't fail the request
		}
	}

	response.Success(c, gin.H{
		"message": "password reset successfully",
	})
}

// swagger:route GET /api/v1/users/{id}/audit-logs users getAuditLogs
//
// 获取用户操作日志。
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: auditLogsResponse
//	400: errorResponse
//	403: errorResponse
//	404: errorResponse
//	500: errorResponse
//
// GetAuditLogs returns user's audit logs with pagination.
func (h *Handler) GetAuditLogs(c *gin.Context) {
	userID, err := strconv.ParseUint(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidUserID, "invalid user id", nil)
		return
	}

	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	// Build query
	query := h.db.Model(&model.AuditLog{}).Where("user_id = ?", userID)

	// Apply filters
	if actionType := c.Query("action_type"); actionType != "" {
		query = query.Where("action = ?", actionType)
	}

	// Count total records
	var total int64
	if err := query.Count(&total).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to count audit logs", nil)
		return
	}

	// Calculate pagination
	offset := (page - 1) * pageSize

	// Fetch logs
	var logs []model.AuditLog
	if err := query.
		Order("created_at DESC").
		Limit(pageSize).
		Offset(offset).
		Find(&logs).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to fetch audit logs", nil)
		return
	}

	// Format response
	logList := make([]gin.H, 0, len(logs))
	for _, log := range logs {
		logItem := gin.H{
			"id":         log.ID,
			"user_id":    log.UserID,
			"action":     log.Action,
			"details":    log.Details,
			"ip":         log.IP,
			"created_at": log.CreatedAt,
		}
		logList = append(logList, logItem)
	}

	response.SuccessWithPagination(c, logList, total, page, pageSize)
}

// swagger:route GET /api/v1/users/{id}/roles users getUserRoles
//
// 获取用户角色列表。
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: userRolesResponse
//	400: errorResponse
//	403: errorResponse
//	404: errorResponse
//	500: errorResponse
//
// GetUserRoles returns user's assigned roles with pagination.
func (h *Handler) GetUserRoles(c *gin.Context) {
	userID, err := strconv.ParseUint(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidUserID, "invalid user id", nil)
		return
	}

	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	// Build query
	query := h.db.Model(&model.UserRole{}).Where("user_id = ?", userID)

	// Count total records
	var total int64
	if err := query.Count(&total).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to count user roles", nil)
		return
	}

	// Calculate pagination
	offset := (page - 1) * pageSize

	// Fetch user roles with role details
	var userRoles []model.UserRole
	if err := query.
		Preload("Role").
		Order("created_at DESC").
		Limit(pageSize).
		Offset(offset).
		Find(&userRoles).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to fetch user roles", nil)
		return
	}

	// Format response
	roleList := make([]gin.H, 0, len(userRoles))
	for _, ur := range userRoles {
		roleItem := gin.H{
			"id":           ur.Role.ID,
			"name":         ur.Role.Name,
			"display_name": ur.Role.DisplayName,
			"description":  ur.Role.Description,
			"is_system":    ur.Role.IsSystem,
			"assigned_at":  ur.CreatedAt,
			"granted_by":   ur.GrantedBy,
		}
		roleList = append(roleList, roleItem)
	}

	response.SuccessWithPagination(c, roleList, total, page, pageSize)
}

// swagger:route GET /api/v1/users/{id}/permissions users getUserPermissions
//
// 获取用户权限列表。
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: userPermissionsResponse
//	400: errorResponse
//	403: errorResponse
//	404: errorResponse
//	500: errorResponse
//
// GetUserPermissions returns user's effective permissions with pagination.
func (h *Handler) GetUserPermissions(c *gin.Context) {
	userID, err := strconv.ParseUint(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidUserID, "invalid user id", nil)
		return
	}

	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	// Get user's roles
	var userRoles []model.UserRole
	if err := h.db.Where("user_id = ?", userID).Preload("Role.Permissions").Find(&userRoles).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to fetch user roles", nil)
		return
	}

	// Collect unique permissions
	permissionMap := make(map[uint64]model.Permission)
	inheritedFrom := make(map[uint64][]string)

	for _, ur := range userRoles {
		for _, perm := range ur.Role.Permissions {
			if _, exists := permissionMap[perm.ID]; !exists {
				permissionMap[perm.ID] = perm
			}
			inheritedFrom[perm.ID] = append(inheritedFrom[perm.ID], ur.Role.Name)
		}
	}

	// Convert to slice for pagination
	var permissions []model.Permission
	for _, perm := range permissionMap {
		permissions = append(permissions, perm)
	}

	// Calculate total before pagination
	total := int64(len(permissions))

	// Apply pagination
	startIdx := (page - 1) * pageSize
	endIdx := startIdx + pageSize
	if startIdx > len(permissions) {
		startIdx = len(permissions)
	}
	if endIdx > len(permissions) {
		endIdx = len(permissions)
	}

	// Get page of permissions
	pagedPermissions := permissions[startIdx:endIdx]

	// Format response
	permList := make([]gin.H, 0, len(pagedPermissions))
	for _, perm := range pagedPermissions {
		permItem := gin.H{
			"id":             perm.ID,
			"name":           perm.Name,
			"resource":       perm.Resource,
			"action":         perm.Action,
			"description":    perm.Description,
			"inherited_from": inheritedFrom[perm.ID],
		}
		permList = append(permList, permItem)
	}

	// Also include role names for reference
	roleNames := make([]string, 0, len(userRoles))
	for _, ur := range userRoles {
		roleNames = append(roleNames, ur.Role.Name)
	}

	// Create response with additional metadata
	responseData := gin.H{
		"data": permList,
		"pagination": gin.H{
			"total":       total,
			"page":        page,
			"page_size":   pageSize,
			"total_pages": int(total)/pageSize + 1,
		},
		"meta": gin.H{
			"roles": roleNames,
		},
	}

	response.Success(c, responseData)
}

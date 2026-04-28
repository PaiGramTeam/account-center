package user

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"paigram/internal/handler/shared"
	"paigram/internal/middleware"
	"paigram/internal/model"
	"paigram/internal/response"
	serviceaudit "paigram/internal/service/audit"
	serviceme "paigram/internal/service/me"
	"paigram/internal/service/user"
	"paigram/internal/sessioncache"
)

// Handler exposes REST handlers for user resources.
type Handler struct {
	userService  UserServiceInterface
	loginMethods LoginMethodService
	sessionCache sessioncache.Store
	db           *gorm.DB // TODO(architectural-refactoring): Remove after migrating remaining 8 methods (UpdateUserStatus, ResetUserPassword, GetAuditLogs, GetUserRoles, GetUserPermissions, GetUserSessions, RevokeUserSession, GetSecuritySummary) to service layer. See docs/superpowers/plans/2026-04-11-architectural-refactoring.md Phase 5
}

// LoginMethodService defines reusable login-method operations shared with /me.
type LoginMethodService interface {
	ListLoginMethods(ctx context.Context, userID uint64) ([]serviceme.LoginMethodView, error)
	SetPrimaryLoginMethod(ctx context.Context, userID uint64, provider string) error
}

// UserServiceInterface defines the interface for user business logic.
type UserServiceInterface interface {
	ListUsers(params user.ListUsersParams) (*user.ListUsersResult, error)
	GetUserByID(userID uint64) (*model.User, error)
	CreateUser(params user.CreateUserParams) (*model.User, error)
	UpdateUser(userID uint64, params user.UpdateUserParams) (*model.User, error)
	DeleteUser(userID uint64) error
	ReplaceUserRoles(userID uint64, roleIDs []uint64, primaryRoleID *uint64, grantedBy uint64) (*model.User, error)
	SetPrimaryRole(userID uint64, primaryRoleID *uint64, clear bool) (*model.User, error)
}

type ReplaceUserRolesRequest struct {
	RoleIDs       []uint64 `json:"role_ids"`
	PrimaryRoleID *uint64  `json:"primary_role_id"`
}

type PatchPrimaryRoleRequest struct {
	PrimaryRoleID *uint64 `json:"primary_role_id"`
}

// NewHandler constructs a handler with the provided user service.
func NewHandler(userService UserServiceInterface) *Handler {
	return &Handler{userService: userService, sessionCache: sessioncache.NewNoopStore()}
}

// NewHandlerWithDB constructs a handler with both service and db (temporary during migration).
func NewHandlerWithDB(userService UserServiceInterface, db *gorm.DB) *Handler {
	return NewHandlerWithDBAndCache(userService, db, sessioncache.NewNoopStore())
}

// NewHandlerWithDBAndCache constructs a handler with both db and session cache dependencies.
func NewHandlerWithDBAndCache(userService UserServiceInterface, db *gorm.DB, cache sessioncache.Store) *Handler {
	if cache == nil {
		cache = sessioncache.NewNoopStore()
	}
	return &Handler{
		userService:  userService,
		loginMethods: serviceme.NewCurrentUserService(db),
		sessionCache: cache,
		db:           db,
	}
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

// ListUsers returns all users with basic profile metadata.
// @Summary List all users
// @Description Get a paginated list of all users with their basic profile information. Supports filtering by status and search query, with customizable sorting options.
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number (starting from 1)" default(1) minimum(1)
// @Param page_size query int false "Number of items per page" default(20) minimum(1) maximum(100)
// @Param sort_by query string false "Sort field (created_at, last_login_at, id)" default(created_at)
// @Param order query string false "Sort order (asc, desc)" default(desc) Enums(asc, desc)
// @Param status query string false "Filter by user status (active, pending, suspended, deleted)"
// @Param search query string false "Search by email or display name"
// @Success 200 {object} UserListResponse "Successfully retrieved user list"
// @Failure 400 {object} gin.H "Invalid request parameters"
// @Failure 401 {object} gin.H "Unauthorized - authentication required"
// @Failure 500 {object} gin.H "Internal server error"
// @Router /api/v1/admin/users [get]
func (h *Handler) ListUsers(c *gin.Context) {
	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
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

	// Call service layer
	result, err := h.userService.ListUsers(user.ListUsersParams{
		Page:     page,
		PageSize: pageSize,
		SortBy:   sortBy,
		Order:    order,
		Status:   status,
		Search:   search,
	})

	if err != nil {
		response.InternalServerError(c, err.Error())
		return
	}

	// Load roles for all users to maintain API compatibility
	userIDs := make([]uint64, len(result.Users))
	for i, u := range result.Users {
		userIDs[i] = u.ID
	}
	rolesByUserID, err := h.loadRoleNamesByUserIDs(h.db, userIDs)
	if err != nil {
		response.InternalServerError(c, "failed to load roles: "+err.Error())
		return
	}

	// Build response with roles
	userList := make([]gin.H, 0, len(result.Users))
	for _, u := range result.Users {
		userList = append(userList, gin.H{
			"id":                 u.ID,
			"primary_login_type": u.PrimaryLoginType,
			"status":             u.Status,
			"display_name":       u.Profile.DisplayName,
			"avatar_url":         u.Profile.AvatarURL,
			"roles":              rolesByUserID[u.ID],
			"last_login_at":      u.LastLoginAt,
			"created_at":         u.CreatedAt,
		})
	}

	response.SuccessWithPagination(c, userList, result.Total, page, pageSize)
}

// GetUser retrieves full details for a user by id.
// @Summary Get user by ID
// @Description Retrieve detailed information for a specific user including profile, emails, roles, permissions, and security metadata. Users can access their own information or require user:read permission for other users.
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Success 200 {object} UserDetailResponse "Successfully retrieved user details"
// @Failure 400 {object} gin.H "Invalid user ID"
// @Failure 401 {object} gin.H "Unauthorized - authentication required"
// @Failure 403 {object} gin.H "Forbidden - insufficient permissions"
// @Failure 404 {object} gin.H "User not found"
// @Failure 500 {object} gin.H "Internal server error"
// @Router /api/v1/admin/users/{id} [get]
func (h *Handler) GetUser(c *gin.Context) {
	id := c.Param("id")
	userID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}

	// Load user with associations for buildUserDetail
	var user model.User
	if err := h.db.Preload("Profile").Preload("Emails").First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFound(c, "user not found")
			return
		}
		response.InternalServerError(c, "failed to load user")
		return
	}

	// Build full user detail with roles, permissions, security metadata
	userData, err := h.buildUserDetail(h.db, user)
	if err != nil {
		response.InternalServerError(c, "failed to build user detail: "+err.Error())
		return
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

func (h *Handler) loadRoleNames(db *gorm.DB, userID uint64) ([]string, error) {
	var userRoles []model.UserRole
	if err := db.Where("user_id = ?", userID).Preload("Role").Order("created_at ASC").Find(&userRoles).Error; err != nil {
		return nil, err
	}

	roles := make([]string, 0, len(userRoles))
	for _, userRole := range userRoles {
		if userRole.Role.Name != "" {
			roles = append(roles, userRole.Role.Name)
		}
	}

	return roles, nil
}

func (h *Handler) loadRoleNamesByUserIDs(db *gorm.DB, userIDs []uint64) (map[uint64][]string, error) {
	result := make(map[uint64][]string, len(userIDs))
	if len(userIDs) == 0 {
		return result, nil
	}

	var userRoles []model.UserRole
	if err := db.Where("user_id IN ?", userIDs).Preload("Role").Order("created_at ASC").Find(&userRoles).Error; err != nil {
		return nil, err
	}

	for _, userRole := range userRoles {
		if userRole.Role.Name == "" {
			continue
		}
		result[userRole.UserID] = append(result[userRole.UserID], userRole.Role.Name)
	}

	return result, nil
}

func (h *Handler) loadPermissionNames(db *gorm.DB, userID uint64) ([]string, error) {
	var permissions []model.Permission
	err := db.Distinct().
		Model(&model.Permission{}).
		Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
		Joins("JOIN user_roles ON user_roles.role_id = role_permissions.role_id").
		Where("user_roles.user_id = ?", userID).
		Order("permissions.name ASC").
		Find(&permissions).Error
	if err != nil {
		return nil, err
	}

	permissionNames := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		permissionNames = append(permissionNames, permission.Name)
	}

	return permissionNames, nil
}

func (h *Handler) loadSecurityMetadata(db *gorm.DB, userID uint64) (bool, int64, error) {
	var twoFactorCount int64
	if err := db.Model(&model.UserTwoFactor{}).Where("user_id = ?", userID).Count(&twoFactorCount).Error; err != nil {
		return false, 0, err
	}

	var activeSessionCount int64
	if err := db.Model(&model.UserSession{}).Where("user_id = ? AND revoked_at IS NULL", userID).Count(&activeSessionCount).Error; err != nil {
		return false, 0, err
	}

	return twoFactorCount > 0, activeSessionCount, nil
}

func (h *Handler) buildUserDetail(db *gorm.DB, user model.User) (UserDetail, error) {
	emails := make([]UserEmailPayload, 0, len(user.Emails))
	for _, email := range user.Emails {
		emails = append(emails, UserEmailPayload{
			Email:      email.Email,
			IsPrimary:  email.IsPrimary,
			VerifiedAt: shared.NullTimePtr(email.VerifiedAt),
		})
	}

	roles, err := h.loadRoleNames(db, user.ID)
	if err != nil {
		return UserDetail{}, err
	}

	permissions, err := h.loadPermissionNames(db, user.ID)
	if err != nil {
		return UserDetail{}, err
	}

	twoFactorEnabled, activeSessionCount, err := h.loadSecurityMetadata(db, user.ID)
	if err != nil {
		return UserDetail{}, err
	}

	return UserDetail{
		ID:                 user.ID,
		Status:             user.Status,
		PrimaryLoginType:   user.PrimaryLoginType,
		DisplayName:        user.Profile.DisplayName,
		AvatarURL:          user.Profile.AvatarURL,
		Bio:                user.Profile.Bio,
		Locale:             user.Profile.Locale,
		PrimaryEmail:       primaryEmail(user.Emails),
		Emails:             emails,
		Roles:              roles,
		Permissions:        permissions,
		TwoFactorEnabled:   twoFactorEnabled,
		ActiveSessionCount: activeSessionCount,
		LastLoginAt:        shared.NullTimePtr(user.LastLoginAt),
		CreatedAt:          user.CreatedAt,
		UpdatedAt:          user.UpdatedAt,
	}, nil
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

// @Summary Get user sessions
// @Description Get a paginated list of all active sessions for a specific user
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param page query int false "Page number (starting from 1)" default(1) minimum(1)
// @Param page_size query int false "Number of items per page" default(20) minimum(1) maximum(100)
// @Success 200 {object} response.PaginatedResponse "Successfully retrieved user sessions"
// @Failure 400 {object} gin.H "Invalid request parameters"
// @Failure 401 {object} gin.H "Unauthorized - authentication required"
// @Failure 403 {object} gin.H "Forbidden - insufficient permissions"
// @Failure 404 {object} gin.H "User not found"
// @Failure 500 {object} gin.H "Internal server error"
// @Router /api/v1/admin/users/{id}/sessions [get]
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

// @Summary Revoke user session
// @Description Revoke a specific active session for a user
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param sessionId path string true "Session ID"
// @Success 204 {object} nil "Session successfully revoked (no content)"
// @Failure 400 {object} gin.H "Invalid request parameters"
// @Failure 401 {object} gin.H "Unauthorized - authentication required"
// @Failure 403 {object} gin.H "Forbidden - insufficient permissions"
// @Failure 404 {object} gin.H "Session not found"
// @Failure 500 {object} gin.H "Internal server error"
// @Router /api/v1/admin/users/{id}/sessions/{sessionId} [delete]
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
	_ = h.sessionCache.Set(c.Request.Context(), sessioncache.RevokedSessionMarkerKey(session.ID), []byte("1"), sessioncache.RevokedSessionMarkerTTL(&session))

	response.Success(c, gin.H{"message": "session revoked successfully"})
}

// @Summary Get security summary
// @Description Get a security status summary for a specific user including two-factor authentication status, active sessions, and device count
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Success 200 {object} user.SecuritySummary "Successfully retrieved security summary"
// @Failure 400 {object} gin.H "Invalid user ID"
// @Failure 401 {object} gin.H "Unauthorized - authentication required"
// @Failure 403 {object} gin.H "Forbidden - insufficient permissions"
// @Failure 404 {object} gin.H "User not found"
// @Failure 500 {object} gin.H "Internal server error"
// @Router /api/v1/admin/users/{id}/security-summary [get]
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

// CreateUser registers a new user account.
// @Summary Create a new user
// @Description Create a new user account with email authentication and profile information. This endpoint requires user:write permission. Role membership is managed via the authority domain. The password will be hashed using bcrypt before storage.
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body CreateUserRequest true "User creation details including email, password, and profile information"
// @Success 201 {object} UserDetailResponse "User created successfully"
// @Failure 400 {object} gin.H "Invalid request body or validation error"
// @Failure 401 {object} gin.H "Unauthorized - authentication required"
// @Failure 403 {object} gin.H "Forbidden - requires user:write permission"
// @Failure 409 {object} gin.H "Email already registered"
// @Failure 500 {object} gin.H "Internal server error"
// @Router /api/v1/admin/users [post]
func (h *Handler) CreateUser(c *gin.Context) {
	var req struct {
		Email            string    `json:"email" binding:"required,email"`
		Password         string    `json:"password" binding:"required,min=8,max=72"`
		DisplayName      string    `json:"display_name" binding:"required,min=1,max=255"`
		PrimaryLoginType string    `json:"primary_login_type" binding:"required,oneof=email google github telegram"`
		AvatarURL        string    `json:"avatar_url" binding:"omitempty,url"`
		Bio              string    `json:"bio" binding:"omitempty,max=500"`
		Locale           string    `json:"locale" binding:"omitempty"`
		Status           string    `json:"status" binding:"omitempty,oneof=pending active suspended deleted"`
		Roles            *[]string `json:"roles"`
	}

	if err := c.ShouldBindBodyWith(&req, binding.JSON); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if req.Roles != nil {
		response.BadRequest(c, "roles must be managed via authorities")
		return
	}
	if model.LoginType(req.PrimaryLoginType) != model.LoginTypeEmail {
		response.BadRequest(c, "primary_login_type=email is required until provider credential provisioning is supported")
		return
	}

	// Normalize and validate email
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		response.BadRequest(c, "email is required")
		return
	}

	// Set defaults
	locale := strings.TrimSpace(req.Locale)
	if locale == "" {
		locale = "en_US"
	}

	status := model.UserStatusPending
	if req.Status != "" {
		status = model.UserStatus(req.Status)
	}

	// Check if email already exists
	var existingEmail model.UserEmail
	if err := h.db.Where("email = ?", email).First(&existingEmail).Error; err == nil {
		response.Conflict(c, "email already registered")
		return
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		response.InternalServerError(c, "failed to check email uniqueness")
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		response.InternalServerError(c, "failed to hash password")
		return
	}

	// Create user with all related records in transaction
	var user model.User
	err = h.db.Transaction(func(tx *gorm.DB) error {
		// 1. Create user with profile
		user = model.User{
			PrimaryLoginType: model.LoginType(req.PrimaryLoginType),
			Status:           status,
			Profile: model.UserProfile{
				DisplayName: strings.TrimSpace(req.DisplayName),
				AvatarURL:   req.AvatarURL,
				Bio:         req.Bio,
				Locale:      locale,
			},
		}

		if err := tx.Create(&user).Error; err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		// 2. Create email record
		userEmail := model.UserEmail{
			UserID:    user.ID,
			Email:     email,
			IsPrimary: true,
		}
		if err := tx.Create(&userEmail).Error; err != nil {
			return fmt.Errorf("failed to create email: %w", err)
		}

		// 3. Create credential with hashed password
		credential := model.UserCredential{
			UserID:            user.ID,
			Provider:          string(model.LoginTypeEmail),
			ProviderAccountID: email,
			PasswordHash:      string(hashedPassword),
		}
		if err := tx.Create(&credential).Error; err != nil {
			return fmt.Errorf("failed to create credential: %w", err)
		}

		return nil
	})

	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			response.Conflict(c, "email already registered")
			return
		}
		response.InternalServerError(c, err.Error())
		return
	}

	// Load full user details with all associations
	var fullUser model.User
	if err := h.db.Preload("Profile").Preload("Emails").First(&fullUser, user.ID).Error; err != nil {
		response.InternalServerError(c, "failed to load created user: "+err.Error())
		return
	}

	// Build complete user detail response
	userData, err := h.buildUserDetail(h.db, fullUser)
	if err != nil {
		response.InternalServerError(c, "failed to build user detail: "+err.Error())
		return
	}

	response.Created(c, userData)
	h.recordAdminUserAudit(c, serviceaudit.WriteInput{
		Category:    "admin_user",
		ActorType:   "admin",
		ActorUserID: currentActorUserID(c),
		Action:      "admin_user_create",
		TargetType:  "user",
		TargetID:    strconv.FormatUint(fullUser.ID, 10),
		OwnerUserID: uint64Ptr(fullUser.ID),
		Result:      "success",
	})
}

// UpdateUser modifies user profile fields and locale.
// @Summary Update user information
// @Description Update user profile fields (display name, avatar, bio) and locale settings. Users can update their own profile or require user:write permission to update other users. Role membership is managed via the authority domain.
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param body body UpdateUserRequest true "User update details - all fields are optional"
// @Success 200 {object} UserDetailResponse "User updated successfully"
// @Failure 400 {object} gin.H "Invalid request body or user ID"
// @Failure 401 {object} gin.H "Unauthorized - authentication required"
// @Failure 403 {object} gin.H "Forbidden - insufficient permissions"
// @Failure 404 {object} gin.H "User not found"
// @Failure 409 {object} gin.H "Conflict - data validation failed"
// @Failure 500 {object} gin.H "Internal server error"
// @Router /api/v1/admin/users/{id} [patch]
func (h *Handler) UpdateUser(c *gin.Context) {
	id := c.Param("id")
	userID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}

	var req struct {
		DisplayName *string   `json:"display_name" binding:"omitempty,min=1,max=255"`
		AvatarURL   *string   `json:"avatar_url" binding:"omitempty,url"`
		Bio         *string   `json:"bio" binding:"omitempty,max=500"`
		Locale      *string   `json:"locale" binding:"omitempty"`
		Roles       *[]string `json:"roles"`
	}

	if err := c.ShouldBindBodyWith(&req, binding.JSON); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if req.Roles != nil {
		response.BadRequest(c, "roles must be managed via authorities")
		return
	}

	// Update user with transaction for multi-table operations
	var user model.User
	err = h.db.Transaction(func(tx *gorm.DB) error {
		// 1. Load existing user with profile
		if err := tx.Preload("Profile").First(&user, userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errors.New("user not found")
			}
			return fmt.Errorf("failed to load user: %w", err)
		}

		// 2. Update profile fields
		updates := map[string]interface{}{}
		if req.DisplayName != nil {
			updates["display_name"] = strings.TrimSpace(*req.DisplayName)
		}
		if req.AvatarURL != nil {
			updates["avatar_url"] = *req.AvatarURL
		}
		if req.Bio != nil {
			updates["bio"] = *req.Bio
		}
		if req.Locale != nil {
			updates["locale"] = strings.TrimSpace(*req.Locale)
		}

		if len(updates) > 0 {
			if err := tx.Model(&model.UserProfile{}).Where("user_id = ?", userID).Updates(updates).Error; err != nil {
				return fmt.Errorf("failed to update profile: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			response.NotFound(c, err.Error())
			return
		}
		if strings.Contains(err.Error(), "already taken") {
			response.Conflict(c, err.Error())
			return
		}
		response.InternalServerError(c, err.Error())
		return
	}

	// Load full user details with all associations
	var fullUser model.User
	if err := h.db.Preload("Profile").Preload("Emails").First(&fullUser, userID).Error; err != nil {
		response.InternalServerError(c, "failed to load updated user: "+err.Error())
		return
	}

	// Build complete user detail response
	userData, err := h.buildUserDetail(h.db, fullUser)
	if err != nil {
		response.InternalServerError(c, "failed to build user detail: "+err.Error())
		return
	}

	response.Success(c, userData)
	h.recordAdminUserAudit(c, serviceaudit.WriteInput{
		Category:    "admin_user",
		ActorType:   "admin",
		ActorUserID: currentActorUserID(c),
		Action:      "admin_user_patch",
		TargetType:  "user",
		TargetID:    strconv.FormatUint(fullUser.ID, 10),
		OwnerUserID: uint64Ptr(fullUser.ID),
		Result:      "success",
	})
}

// DeleteUser soft-deletes a user account, or hard-deletes if ?hard_delete=true.
// @Summary Delete user
// @Description Soft-delete a user account by default (sets deleted_at timestamp), or permanently remove from database with hard_delete=true query parameter. This endpoint requires user:delete permission. Soft-deleted users can potentially be restored.
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param hard_delete query bool false "Permanently delete user from database (cannot be undone)" default(false)
// @Success 204 "User deleted successfully - no content returned"
// @Failure 400 {object} gin.H "Invalid user ID"
// @Failure 401 {object} gin.H "Unauthorized - authentication required"
// @Failure 403 {object} gin.H "Forbidden - requires user:delete permission"
// @Failure 404 {object} gin.H "User not found"
// @Failure 500 {object} gin.H "Internal server error"
// @Router /api/v1/admin/users/{id} [delete]
func (h *Handler) DeleteUser(c *gin.Context) {
	id := c.Param("id")
	userID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}

	// Support hard delete via query parameter
	hardDelete := c.Query("hard_delete") == "true"

	if hardDelete {
		// Hard delete: bypass service layer, use direct DB access with Unscoped
		result := h.db.Unscoped().Delete(&model.User{}, userID)
		if result.Error != nil {
			response.InternalServerError(c, "failed to delete user: "+result.Error.Error())
			return
		}
		if result.RowsAffected == 0 {
			response.NotFound(c, "user not found")
			return
		}
	} else {
		// Soft delete: use service layer
		if err := h.userService.DeleteUser(userID); err != nil {
			if strings.Contains(err.Error(), "not found") {
				response.NotFound(c, err.Error())
				return
			}
			response.InternalServerError(c, err.Error())
			return
		}
	}

	c.Status(204)
}

// swagger:route PATCH /api/v1/admin/users/{id}/status users updateUserStatus
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
	h.recordAdminUserAudit(c, serviceaudit.WriteInput{
		Category:    "admin_user",
		ActorType:   "admin",
		ActorUserID: currentActorUserID(c),
		Action:      "admin_user_disable",
		TargetType:  "user",
		TargetID:    strconv.FormatUint(user.ID, 10),
		OwnerUserID: uint64Ptr(user.ID),
		Result:      "success",
		Metadata: map[string]any{
			"status": status,
		},
	})
}

// swagger:route POST /api/v1/admin/users/{id}/reset-password users resetUserPassword
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
	h.recordAdminUserAudit(c, serviceaudit.WriteInput{
		Category:    "admin_user",
		ActorType:   "admin",
		ActorUserID: currentActorUserID(c),
		Action:      "admin_user_reset_password",
		TargetType:  "user",
		TargetID:    strconv.FormatUint(user.ID, 10),
		OwnerUserID: uint64Ptr(user.ID),
		Result:      "success",
		Metadata: map[string]any{
			"invalidate_sessions": req.InvalidateSessions,
		},
	})
}

// swagger:route GET /api/v1/admin/users/{id}/audit-logs users getAuditLogs
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

// swagger:route GET /api/v1/admin/users/{id}/roles users getUserRoles
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

// PutUserRoles replaces a user's role assignments.
// @Summary Replace user roles
// @Description Replace the full role assignment set for a user and optionally update the primary role.
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param body body ReplaceUserRolesRequest true "Role replacement payload"
// @Success 200 {object} gin.H
// @Failure 400 {object} gin.H
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 422 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/admin/users/{id}/roles [put]
func (h *Handler) PutUserRoles(c *gin.Context) {
	targetUserID, err := strconv.ParseUint(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidUserID, "invalid user id", nil)
		return
	}

	actorUserID, ok := middleware.GetUserID(c)
	if !ok || actorUserID == 0 {
		response.Unauthorized(c, "authentication required")
		return
	}

	var req ReplaceUserRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request payload")
		return
	}

	updatedUser, err := h.userService.ReplaceUserRoles(targetUserID, req.RoleIDs, req.PrimaryRoleID, actorUserID)
	if err != nil {
		writeUserRoleMutationError(c, err)
		return
	}

	response.Success(c, gin.H{"primary_role_id": nullableUserRoleID(updatedUser.PrimaryRoleID)})
	h.recordAdminUserAudit(c, serviceaudit.WriteInput{
		Category:    "admin_user",
		ActorType:   "admin",
		ActorUserID: uint64Ptr(actorUserID),
		Action:      "admin_user_role_assignment",
		TargetType:  "user",
		TargetID:    strconv.FormatUint(targetUserID, 10),
		OwnerUserID: uint64Ptr(targetUserID),
		Result:      "success",
		Metadata: map[string]any{
			"role_ids":        req.RoleIDs,
			"primary_role_id": req.PrimaryRoleID,
		},
	})
}

// PatchPrimaryRole updates a user's primary role.
// @Summary Patch primary role
// @Description Update or clear the primary role for a user.
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param body body PatchPrimaryRoleRequest true "Primary role patch payload"
// @Success 200 {object} gin.H
// @Failure 400 {object} gin.H
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 422 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/admin/users/{id}/primary-role [patch]
func (h *Handler) PatchPrimaryRole(c *gin.Context) {
	targetUserID, err := strconv.ParseUint(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidUserID, "invalid user id", nil)
		return
	}

	var raw map[string]json.RawMessage
	if err := c.ShouldBindJSON(&raw); err != nil {
		response.BadRequest(c, "invalid request payload")
		return
	}

	rawPrimaryRoleID, ok := raw["primary_role_id"]
	if !ok {
		response.BadRequest(c, "primary_role_id is required")
		return
	}

	clear := string(rawPrimaryRoleID) == "null"
	var req PatchPrimaryRoleRequest
	if !clear {
		if err := json.Unmarshal(rawPrimaryRoleID, &req.PrimaryRoleID); err != nil {
			response.BadRequest(c, "invalid request payload")
			return
		}
	}

	updatedUser, err := h.userService.SetPrimaryRole(targetUserID, req.PrimaryRoleID, clear)
	if err != nil {
		writeUserRoleMutationError(c, err)
		return
	}

	response.Success(c, gin.H{"primary_role_id": nullableUserRoleID(updatedUser.PrimaryRoleID)})
	h.recordAdminUserAudit(c, serviceaudit.WriteInput{
		Category:    "admin_user",
		ActorType:   "admin",
		ActorUserID: currentActorUserID(c),
		Action:      "admin_user_primary_role_change",
		TargetType:  "user",
		TargetID:    strconv.FormatUint(targetUserID, 10),
		OwnerUserID: uint64Ptr(targetUserID),
		Result:      "success",
		Metadata: map[string]any{
			"clear":           clear,
			"primary_role_id": req.PrimaryRoleID,
		},
	})
}

func (h *Handler) recordAdminUserAudit(c *gin.Context, input serviceaudit.WriteInput) {
	if h.db == nil {
		return
	}
	input.RequestID = c.GetHeader("X-Request-ID")
	input.IP = c.ClientIP()
	input.UserAgent = c.Request.UserAgent()
	_ = serviceaudit.Record(c.Request.Context(), h.db, input)
}

func currentActorUserID(c *gin.Context) *uint64 {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		return nil
	}
	return uint64Ptr(userID)
}

func uint64Ptr(value uint64) *uint64 {
	if value == 0 {
		return nil
	}
	return &value
}

// swagger:route GET /api/v1/admin/users/{id}/permissions users getUserPermissions
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

	var existingUser model.User
	if err := h.db.Select("id").First(&existingUser, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFound(c, "user not found")
			return
		}
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to load user", nil)
		return
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
	sort.Slice(permissions, func(i, j int) bool {
		if permissions[i].Resource != permissions[j].Resource {
			return permissions[i].Resource < permissions[j].Resource
		}
		if permissions[i].Action != permissions[j].Action {
			return permissions[i].Action < permissions[j].Action
		}
		if permissions[i].Name != permissions[j].Name {
			return permissions[i].Name < permissions[j].Name
		}
		return permissions[i].ID < permissions[j].ID
	})
	for permissionID := range inheritedFrom {
		sort.Strings(inheritedFrom[permissionID])
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
	sort.Strings(roleNames)

	response.SuccessWithPaginationMeta(c, permList, total, page, pageSize, gin.H{
		"roles": roleNames,
	})
}

func writeUserRoleMutationError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, user.ErrUserNotFound):
		response.NotFound(c, "user not found")
	case errors.Is(err, user.ErrRoleNotFound):
		response.Error(c, http.StatusUnprocessableEntity, "role not found")
	case errors.Is(err, user.ErrPrimaryRoleNotAssigned):
		response.Error(c, http.StatusUnprocessableEntity, "primary role must belong to user")
	default:
		response.InternalServerError(c, "failed to update user roles")
	}
}

func nullableUserRoleID(value sql.NullInt64) any {
	if !value.Valid {
		return nil
	}
	return value.Int64
}

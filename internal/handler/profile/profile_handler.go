package profile

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/handler/shared"
	"paigram/internal/model"
	"paigram/internal/response"
)

// Handler manages profile-related endpoints.
type Handler struct {
	db           *gorm.DB
	cfg          config.AuthConfig
	emailHandler *EmailHandler
}

// NewHandler constructs a profile handler.
func NewHandler(db *gorm.DB, cfg config.AuthConfig) *Handler {
	return &Handler{
		db:           db,
		cfg:          cfg,
		emailHandler: NewEmailHandler(db, cfg),
	}
}

// RegisterRoutes binds profile endpoints beneath the given route group.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.GET("/:id", h.GetProfile)
	rg.PATCH("/:id", h.UpdateProfile)

	// Account binding endpoints
	rg.GET("/:id/accounts", h.GetBoundAccounts)
	rg.POST("/:id/accounts/bind", h.BindAccount)
	rg.DELETE("/:id/accounts/:provider", h.UnbindAccount)

	// Email management endpoints
	h.emailHandler.RegisterEmailRoutes(rg)
}

// RegisterEmailRoutes binds email management endpoints beneath the given route group.
func (h *Handler) RegisterEmailRoutes(rg *gin.RouterGroup) {
	h.emailHandler.RegisterEmailRoutes(rg)
}

// swagger:route GET /api/v1/profiles/{id} profile getProfile
//
// Get user profile.
//
// Retrieves detailed profile information for a specific user including
// display name, avatar, bio, emails, and account status.
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: profileResponse
//	400: profileErrorResponse
//	404: profileErrorResponse
//	500: profileErrorResponse
//
// GetProfile returns profile + email overview for a user.
func (h *Handler) GetProfile(c *gin.Context) {
	userID, err := parseUintID(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}

	var user model.User
	if err := h.db.Preload("Profile").Preload("Emails").First(&user, userID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			response.NotFound(c, "user not found")
			return
		}
		response.InternalServerError(c, "failed to load profile")
		return
	}

	primaryEmail := ""
	emails := make([]gin.H, 0, len(user.Emails))
	for _, email := range user.Emails {
		if email.IsPrimary {
			primaryEmail = email.Email
		}
		emails = append(emails, gin.H{
			"email":       email.Email,
			"is_primary":  email.IsPrimary,
			"verified_at": shared.NullTimePtr(email.VerifiedAt),
		})
	}

	response.Success(c, gin.H{
		"user_id":       user.ID,
		"display_name":  user.Profile.DisplayName,
		"avatar_url":    user.Profile.AvatarURL,
		"bio":           user.Profile.Bio,
		"locale":        user.Profile.Locale,
		"status":        user.Status,
		"primary_email": primaryEmail,
		"emails":        emails,
		"last_login_at": shared.NullTimePtr(user.LastLoginAt),
		"created_at":    user.CreatedAt,
		"updated_at":    user.UpdatedAt,
	})
}

type updateProfileRequest struct {
	DisplayName *string `json:"display_name"`
	AvatarURL   *string `json:"avatar_url"`
	Bio         *string `json:"bio"`
	Locale      *string `json:"locale"`
}

// swagger:route PATCH /api/v1/profiles/{id} profile updateProfile
//
// Update user profile.
//
// Updates profile fields for a specific user. Only provided fields will be updated.
//
// Consumes:
//   - application/json
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: updateProfileResponse
//	400: profileErrorResponse
//	404: profileErrorResponse
//	500: profileErrorResponse
//
// UpdateProfile modifies profile fields.
func (h *Handler) UpdateProfile(c *gin.Context) {
	userID, err := parseUintID(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}

	var req updateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	var profile model.UserProfile
	if err := h.db.Where("user_id = ?", userID).First(&profile).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			response.NotFound(c, "profile not found")
			return
		}
		response.InternalServerError(c, "failed to load profile")
		return
	}

	updates := map[string]interface{}{}
	if req.DisplayName != nil {
		updates["display_name"] = strings.TrimSpace(*req.DisplayName)
	}
	if req.AvatarURL != nil {
		updates["avatar_url"] = strings.TrimSpace(*req.AvatarURL)
	}
	if req.Bio != nil {
		updates["bio"] = strings.TrimSpace(*req.Bio)
	}
	if req.Locale != nil {
		updates["locale"] = strings.TrimSpace(*req.Locale)
	}

	if len(updates) == 0 {
		response.BadRequest(c, "no fields to update")
		return
	}

	if err := h.db.Model(&model.UserProfile{}).Where("id = ?", profile.ID).Updates(updates).Error; err != nil {
		response.InternalServerError(c, "failed to update profile")
		return
	}

	if err := h.db.Where("id = ?", profile.ID).First(&profile).Error; err != nil {
		response.InternalServerError(c, "failed to reload profile")
		return
	}

	response.Success(c, gin.H{
		"user_id":      profile.UserID,
		"display_name": profile.DisplayName,
		"avatar_url":   profile.AvatarURL,
		"bio":          profile.Bio,
		"locale":       profile.Locale,
	})
}

func parseUintID(raw string) (uint64, error) {
	return strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
}

// GetBoundAccounts returns list of bound third-party accounts
// swagger:route GET /api/v1/profiles/{id}/accounts profile getBoundAccounts
//
// Get bound third-party accounts with pagination.
//
// Retrieves a paginated list of all third-party accounts bound to a user profile.
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: paginatedResponse
//	400: profileErrorResponse
//	404: profileErrorResponse
//	500: profileErrorResponse
func (h *Handler) GetBoundAccounts(c *gin.Context) {
	userID, err := parseUintID(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}

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

	// Load user to check primary login type
	var user model.User
	if err := h.db.First(&user, userID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			response.NotFound(c, "user not found")
			return
		}
		response.InternalServerError(c, "failed to load user")
		return
	}

	// Count total bound accounts
	var total int64
	if err := h.db.Model(&model.UserCredential{}).
		Where("user_id = ? AND provider != ?", userID, "email").
		Count(&total).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to count bound accounts", nil)
		return
	}

	// Get paginated credentials
	var credentials []model.UserCredential
	offset := (page - 1) * pageSize

	if err := h.db.Where("user_id = ? AND provider != ?", userID, "email").
		Order("created_at DESC").
		Limit(pageSize).
		Offset(offset).
		Find(&credentials).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to load bound accounts", nil)
		return
	}

	accounts := make([]gin.H, 0, len(credentials))
	for _, cred := range credentials {
		displayName := cred.ProviderAccountID // Default to provider account ID
		avatarURL := ""

		// Parse metadata if available
		if cred.Metadata != "" {
			var metadata map[string]interface{}
			if err := json.Unmarshal([]byte(cred.Metadata), &metadata); err == nil {
				if name, ok := metadata["display_name"].(string); ok && name != "" {
					displayName = name
				}
				if avatar, ok := metadata["avatar_url"].(string); ok {
					avatarURL = avatar
				}
			}
		}

		// Determine if this is the primary login method
		isPrimary := false
		if user.PrimaryLoginType == model.LoginTypeOAuth && cred.Provider != "email" {
			// For OAuth primary login, we would need to check which provider
			// For now, we'll mark the first OAuth provider as primary
			// This could be improved with more specific logic
			isPrimary = len(accounts) == 0
		}

		accounts = append(accounts, gin.H{
			"provider":            cred.Provider,
			"provider_account_id": cred.ProviderAccountID,
			"display_name":        displayName,
			"avatar_url":          avatarURL,
			"bound_at":            cred.CreatedAt,
			"last_used_at":        shared.NullTimePtr(cred.LastSyncAt),
			"is_primary":          isPrimary,
		})
	}

	response.SuccessWithPagination(c, accounts, total, page, pageSize)
}

type bindAccountRequest struct {
	Provider     string                 `json:"provider" binding:"required"`
	ProviderData map[string]interface{} `json:"provider_data" binding:"required"`
}

// BindAccount binds a new third-party account
// swagger:route POST /api/v1/profiles/{id}/accounts/bind profile bindAccount
//
// Bind third-party account.
//
// Binds a new third-party account to user profile.
//
// Consumes:
//   - application/json
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: bindAccountResponse
//	400: profileErrorResponse
//	404: profileErrorResponse
//	409: profileErrorResponse
//	500: profileErrorResponse
func (h *Handler) BindAccount(c *gin.Context) {
	userID, err := parseUintID(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}

	var req bindAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	// Validate provider
	validProviders := []string{"telegram", "google", "github"}
	isValidProvider := false
	for _, p := range validProviders {
		if req.Provider == p {
			isValidProvider = true
			break
		}
	}
	if !isValidProvider {
		response.BadRequest(c, "invalid provider")
		return
	}

	// Begin transaction
	tx := h.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Verify user exists
	var user model.User
	if err := tx.First(&user, userID).Error; err != nil {
		tx.Rollback()
		if err == gorm.ErrRecordNotFound {
			response.NotFound(c, "user not found")
			return
		}
		response.InternalServerError(c, "failed to load user")
		return
	}

	// Extract provider account ID based on provider type
	var providerAccountID string
	var displayName string
	var avatarURL string

	switch req.Provider {
	case "telegram":
		// Telegram provider data should contain id, first_name, username, etc.
		if id, ok := req.ProviderData["id"].(float64); ok {
			providerAccountID = fmt.Sprintf("%.0f", id)
		}
		if firstName, ok := req.ProviderData["first_name"].(string); ok {
			displayName = firstName
		}
		if lastName, ok := req.ProviderData["last_name"].(string); ok && lastName != "" {
			displayName = displayName + " " + lastName
		}
		if username, ok := req.ProviderData["username"].(string); ok && username != "" {
			displayName = displayName + " (@" + username + ")"
		}
		// Telegram doesn't provide avatar URL in auth data

	case "google":
		// Google provider data should contain sub (subject/ID), email, name, picture
		if sub, ok := req.ProviderData["sub"].(string); ok {
			providerAccountID = sub
		}
		if name, ok := req.ProviderData["name"].(string); ok {
			displayName = name
		}
		if picture, ok := req.ProviderData["picture"].(string); ok {
			avatarURL = picture
		}

	case "github":
		// GitHub provider data should contain id, login, name, avatar_url
		if id, ok := req.ProviderData["id"].(float64); ok {
			providerAccountID = fmt.Sprintf("%.0f", id)
		}
		if name, ok := req.ProviderData["name"].(string); ok && name != "" {
			displayName = name
		} else if login, ok := req.ProviderData["login"].(string); ok {
			displayName = login
		}
		if avatar, ok := req.ProviderData["avatar_url"].(string); ok {
			avatarURL = avatar
		}
	}

	if providerAccountID == "" {
		tx.Rollback()
		response.BadRequest(c, "invalid provider data: missing account ID")
		return
	}

	// Check if provider is already bound to any user
	var existingCred model.UserCredential
	err = tx.Where("provider = ? AND provider_account_id = ?", req.Provider, providerAccountID).First(&existingCred).Error
	if err == nil {
		tx.Rollback()
		if existingCred.UserID == userID {
			response.Conflict(c, "provider already bound to this account")
		} else {
			response.Conflict(c, "provider already bound to another account")
		}
		return
	} else if err != gorm.ErrRecordNotFound {
		tx.Rollback()
		response.InternalServerError(c, "failed to check existing binding")
		return
	}

	// Create metadata JSON
	metadata := gin.H{
		"display_name": displayName,
		"avatar_url":   avatarURL,
		"bound_via":    "manual_binding",
		"bound_at":     time.Now().UTC(),
	}
	metadataJSON, _ := json.Marshal(metadata)

	// Create the credential
	credential := model.UserCredential{
		UserID:            userID,
		Provider:          req.Provider,
		ProviderAccountID: providerAccountID,
		Metadata:          string(metadataJSON),
	}

	if err := tx.Create(&credential).Error; err != nil {
		tx.Rollback()
		response.InternalServerError(c, "failed to bind account")
		return
	}

	// Commit transaction
	tx.Commit()

	response.Success(c, gin.H{
		"message": "account bound successfully",
		"data": gin.H{
			"provider":            credential.Provider,
			"provider_account_id": credential.ProviderAccountID,
			"display_name":        displayName,
			"avatar_url":          avatarURL,
			"bound_at":            credential.CreatedAt,
		},
	})
}

// UnbindAccount removes a third-party account binding
// swagger:route DELETE /api/v1/profiles/{id}/accounts/{provider} profile unbindAccount
//
// Unbind third-party account.
//
// Removes a third-party account binding from user profile.
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: unbindAccountResponse
//	400: profileErrorResponse
//	404: profileErrorResponse
//	403: profileErrorResponse
//	500: profileErrorResponse
func (h *Handler) UnbindAccount(c *gin.Context) {
	userID, err := parseUintID(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}

	provider := strings.TrimSpace(c.Param("provider"))
	if provider == "" {
		response.BadRequest(c, "provider is required")
		return
	}

	// Load user to check login methods
	var user model.User
	if err := h.db.Preload("Credentials").First(&user, userID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			response.NotFound(c, "user not found")
			return
		}
		response.InternalServerError(c, "failed to load user")
		return
	}

	// Check if user has at least one other login method
	loginMethodCount := 0
	var targetCred *model.UserCredential

	for i := range user.Credentials {
		if user.Credentials[i].Provider == provider {
			targetCred = &user.Credentials[i]
		} else {
			loginMethodCount++
		}
	}

	if targetCred == nil {
		response.NotFound(c, "provider not bound to this account")
		return
	}

	// Check if this is the last login method
	if loginMethodCount == 0 {
		response.Forbidden(c, "cannot remove the last login method")
		return
	}

	// Check if trying to unbind primary login method
	if user.PrimaryLoginType == model.LoginTypeOAuth && provider != "email" {
		// Additional check might be needed based on provider
		response.Forbidden(c, "cannot unbind primary login method")
		return
	}

	// Delete the credential
	if err := h.db.Delete(&model.UserCredential{}, targetCred.ID).Error; err != nil {
		response.InternalServerError(c, "failed to unbind account")
		return
	}

	response.Success(c, gin.H{
		"message": "account unbound successfully",
	})
}

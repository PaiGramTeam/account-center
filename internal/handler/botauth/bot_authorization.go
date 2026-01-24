package botauth

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"paigram/internal/logging"
	"paigram/internal/middleware"
	"paigram/internal/model"
	"paigram/internal/response"
)

// Handler handles bot authorization endpoints
type Handler struct {
	db *gorm.DB
}

// NewHandler creates a new bot authorization handler
func NewHandler(db *gorm.DB) *Handler {
	return &Handler{db: db}
}

// RegisterRoutes registers bot authorization routes
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.GET("", h.ListBotAuthorizations)
	rg.POST("", h.AuthorizeBot)
	rg.GET("/:id", h.GetBotAuthorization)
	rg.DELETE("/:id", h.RevokeBotAuthorization)
}

// ListBotAuthorizationsRequest is the request for listing bot authorizations
type ListBotAuthorizationsRequest struct {
	Page     int  `form:"page" binding:"omitempty,min=1"`
	PageSize int  `form:"page_size" binding:"omitempty,min=1,max=100"`
	Active   bool `form:"active"`
}

// AuthorizeBotRequest is the request payload for authorizing a bot
type AuthorizeBotRequest struct {
	BotID      string   `json:"bot_id" binding:"required"`
	Scopes     []string `json:"scopes" binding:"required,min=1"`
	ExpiryDays int      `json:"expiry_days" binding:"omitempty,min=1,max=365"`
}

// ListBotAuthorizations returns all bot authorizations for the current user
// @Summary List bot authorizations
// @Description Get all bot authorizations for the current user
// @Tags bot-authorization
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param active query bool false "Filter active authorizations only"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/bot-authorizations [get]
func (h *Handler) ListBotAuthorizations(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		response.UnauthorizedWithCode(c, "UNAUTHORIZED", "user not authenticated", nil)
		return
	}

	var req ListBotAuthorizationsRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		response.BadRequestWithCode(c, "INVALID_INPUT", "invalid request", map[string]string{
			"error": err.Error(),
		})
		return
	}

	// Set defaults
	if req.Page == 0 {
		req.Page = 1
	}
	if req.PageSize == 0 {
		req.PageSize = 20
	}

	query := h.db.Preload("Bot").Where("user_id = ?", userID)

	if req.Active {
		query = query.Where("revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)", time.Now())
	}

	// Count total
	var total int64
	if err := query.Model(&model.BotAuthorization{}).Count(&total).Error; err != nil {
		logging.Error("failed to count bot authorizations",
			zap.Error(err),
			zap.Uint64("user_id", userID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Get authorizations
	var authorizations []model.BotAuthorization
	offset := (req.Page - 1) * req.PageSize
	if err := query.Offset(offset).Limit(req.PageSize).Order("created_at DESC").Find(&authorizations).Error; err != nil {
		logging.Error("failed to query bot authorizations",
			zap.Error(err),
			zap.Uint64("user_id", userID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Build response
	responses := make([]model.BotAuthorizationResponse, 0, len(authorizations))
	for _, auth := range authorizations {
		var scopes []string
		if err := json.Unmarshal([]byte(auth.Scopes), &scopes); err != nil {
			logging.Warn("failed to unmarshal scopes",
				zap.Error(err),
				zap.Uint64("auth_id", auth.ID),
			)
			scopes = []string{}
		}

		responses = append(responses, model.BotAuthorizationResponse{
			ID:           auth.ID,
			BotID:        auth.BotID,
			BotName:      auth.Bot.Name,
			BotType:      auth.Bot.Type,
			Description:  auth.Bot.Description,
			Scopes:       scopes,
			AuthorizedAt: auth.AuthorizedAt,
			LastUsedAt:   auth.LastUsedAt,
			ExpiresAt:    auth.ExpiresAt,
		})
	}

	totalPages := int((total + int64(req.PageSize) - 1) / int64(req.PageSize))

	response.Success(c, gin.H{
		"data": responses,
		"pagination": gin.H{
			"total":       total,
			"page":        req.Page,
			"page_size":   req.PageSize,
			"total_pages": totalPages,
		},
	})
}

// GetBotAuthorization returns a specific bot authorization
// @Summary Get bot authorization
// @Description Get details of a specific bot authorization
// @Tags bot-authorization
// @Accept json
// @Produce json
// @Param id path int true "Authorization ID"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/bot-authorizations/{id} [get]
func (h *Handler) GetBotAuthorization(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		response.UnauthorizedWithCode(c, "UNAUTHORIZED", "user not authenticated", nil)
		return
	}

	id := c.Param("id")
	if id == "" {
		response.BadRequestWithCode(c, "INVALID_ID", "authorization ID is required", nil)
		return
	}

	var auth model.BotAuthorization
	if err := h.db.Preload("Bot").Where("id = ? AND user_id = ?", id, userID).First(&auth).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFoundWithCode(c, "NOT_FOUND", "bot authorization not found", nil)
			return
		}
		logging.Error("failed to query bot authorization",
			zap.Error(err),
			zap.String("id", id),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	var scopes []string
	if err := json.Unmarshal([]byte(auth.Scopes), &scopes); err != nil {
		logging.Warn("failed to unmarshal scopes",
			zap.Error(err),
			zap.Uint64("auth_id", auth.ID),
		)
		scopes = []string{}
	}

	resp := model.BotAuthorizationResponse{
		ID:           auth.ID,
		BotID:        auth.BotID,
		BotName:      auth.Bot.Name,
		BotType:      auth.Bot.Type,
		Description:  auth.Bot.Description,
		Scopes:       scopes,
		AuthorizedAt: auth.AuthorizedAt,
		LastUsedAt:   auth.LastUsedAt,
		ExpiresAt:    auth.ExpiresAt,
	}

	response.Success(c, resp)
}

// AuthorizeBot authorizes a bot to access user data
// @Summary Authorize bot
// @Description Grant authorization for a bot to access user data with specified scopes
// @Tags bot-authorization
// @Accept json
// @Produce json
// @Param request body AuthorizeBotRequest true "Authorization request"
// @Security BearerAuth
// @Success 201 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 409 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/bot-authorizations [post]
func (h *Handler) AuthorizeBot(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		response.UnauthorizedWithCode(c, "UNAUTHORIZED", "user not authenticated", nil)
		return
	}

	var req AuthorizeBotRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequestWithCode(c, "INVALID_INPUT", "invalid request", map[string]string{
			"error": err.Error(),
		})
		return
	}

	// Check if bot exists
	var bot model.Bot
	if err := h.db.Where("bot_id = ?", req.BotID).First(&bot).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFoundWithCode(c, "BOT_NOT_FOUND", "bot not found", nil)
			return
		}
		logging.Error("failed to query bot",
			zap.Error(err),
			zap.String("bot_id", req.BotID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Check if authorization already exists
	var existing model.BotAuthorization
	err := h.db.Where("user_id = ? AND bot_id = ?", userID, req.BotID).First(&existing).Error
	if err == nil {
		// Authorization exists
		if existing.RevokedAt == nil {
			response.ConflictWithCode(c, "ALREADY_AUTHORIZED", "bot already authorized", nil)
			return
		}
		// Revoked authorization exists, we can create a new one
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		logging.Error("failed to check existing authorization",
			zap.Error(err),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Marshal scopes to JSON
	scopesJSON, err := json.Marshal(req.Scopes)
	if err != nil {
		logging.Error("failed to marshal scopes",
			zap.Error(err),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Create authorization
	auth := model.BotAuthorization{
		UserID:       userID,
		BotID:        req.BotID,
		Scopes:       string(scopesJSON),
		AuthorizedAt: time.Now(),
	}

	if req.ExpiryDays > 0 {
		expiryTime := time.Now().AddDate(0, 0, req.ExpiryDays)
		auth.ExpiresAt = &expiryTime
	}

	if err := h.db.Create(&auth).Error; err != nil {
		logging.Error("failed to create bot authorization",
			zap.Error(err),
			zap.Uint64("user_id", userID),
			zap.String("bot_id", req.BotID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Reload with bot details
	if err := h.db.Preload("Bot").First(&auth, auth.ID).Error; err != nil {
		logging.Warn("failed to reload authorization with bot details",
			zap.Error(err),
		)
	}

	resp := model.BotAuthorizationResponse{
		ID:           auth.ID,
		BotID:        auth.BotID,
		BotName:      auth.Bot.Name,
		BotType:      auth.Bot.Type,
		Description:  auth.Bot.Description,
		Scopes:       req.Scopes,
		AuthorizedAt: auth.AuthorizedAt,
		ExpiresAt:    auth.ExpiresAt,
	}

	response.Created(c, resp)
}

// RevokeBotAuthorization revokes a bot authorization
// @Summary Revoke bot authorization
// @Description Revoke authorization for a bot to access user data
// @Tags bot-authorization
// @Accept json
// @Produce json
// @Param id path int true "Authorization ID"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/bot-authorizations/{id} [delete]
func (h *Handler) RevokeBotAuthorization(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		response.UnauthorizedWithCode(c, "UNAUTHORIZED", "user not authenticated", nil)
		return
	}

	id := c.Param("id")
	if id == "" {
		response.BadRequestWithCode(c, "INVALID_ID", "authorization ID is required", nil)
		return
	}

	var auth model.BotAuthorization
	if err := h.db.Where("id = ? AND user_id = ?", id, userID).First(&auth).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFoundWithCode(c, "NOT_FOUND", "bot authorization not found", nil)
			return
		}
		logging.Error("failed to query bot authorization",
			zap.Error(err),
			zap.String("id", id),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	if auth.RevokedAt != nil {
		response.Success(c, gin.H{
			"message": "authorization already revoked",
		})
		return
	}

	// Revoke authorization
	now := time.Now()
	updates := map[string]interface{}{
		"revoked_at":    &now,
		"revoked_by":    &userID,
		"revoke_reason": "revoked by user",
	}

	if err := h.db.Model(&auth).Updates(updates).Error; err != nil {
		logging.Error("failed to revoke bot authorization",
			zap.Error(err),
			zap.Uint64("auth_id", auth.ID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	response.Success(c, gin.H{
		"message": "bot authorization revoked successfully",
	})
}

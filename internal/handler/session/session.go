package session

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"paigram/internal/logging"
	"paigram/internal/middleware"
	"paigram/internal/model"
	"paigram/internal/response"
	"paigram/internal/sessioncache"
)

// hashToken creates SHA-256 hash of token
func hashToken(token string) string {
	if token == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// generateDeviceID creates a unique device identifier from user agent and IP
// This matches the implementation in auth/token.go
func generateDeviceID(userAgent, clientIP string) string {
	data := userAgent + clientIP
	hash := sha256.Sum256([]byte(data))
	return base64.URLEncoding.EncodeToString(hash[:])[:22]
}

// Handler handles session management endpoints
type Handler struct {
	db           *gorm.DB
	sessionCache sessioncache.Store
}

// NewHandler creates a new session handler
func NewHandler(db *gorm.DB, cache sessioncache.Store) *Handler {
	return &Handler{
		db:           db,
		sessionCache: cache,
	}
}

// RegisterRoutes registers session management routes
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.GET("", h.ListSessions)
	rg.DELETE("/:id", h.RevokeSession)
	rg.DELETE("", h.RevokeAllSessions)
}

// SessionResponse represents the API response for a session
type SessionResponse struct {
	ID            uint64    `json:"id"`
	DeviceID      string    `json:"device_id"`
	DeviceName    string    `json:"device_name,omitempty"`
	DeviceType    string    `json:"device_type,omitempty"`
	IP            string    `json:"ip,omitempty"`
	Location      string    `json:"location,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	LastActiveAt  time.Time `json:"last_active_at,omitempty"`
	AccessExpiry  time.Time `json:"access_expiry"`
	RefreshExpiry time.Time `json:"refresh_expiry"`
	IsCurrent     bool      `json:"is_current"`
}

// ListSessions returns all active sessions for the current user
// @Summary List user sessions
// @Description Get all active sessions for the current user
// @Tags sessions
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 500 {object} response.Response
func (h *Handler) ListSessions(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		response.UnauthorizedWithCode(c, "UNAUTHORIZED", "user not authenticated", nil)
		return
	}

	// Get current session token hash for comparison
	authHeader := c.GetHeader("Authorization")
	var currentTokenHash string
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		currentToken := authHeader[7:]
		currentTokenHash = hashToken(currentToken)
	}

	var sessions []model.UserSession
	// Preload related user devices for better response
	if err := h.db.Where("user_id = ? AND revoked_at IS NULL", userID).
		Order("created_at DESC").
		Find(&sessions).Error; err != nil {
		logging.Error("failed to query user sessions",
			zap.Error(err),
			zap.Uint64("user_id", userID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Get all user devices for device information
	var devices []model.UserDevice
	deviceMap := make(map[string]*model.UserDevice)
	if err := h.db.Where("user_id = ?", userID).Find(&devices).Error; err == nil {
		for i := range devices {
			deviceMap[devices[i].DeviceID] = &devices[i]
		}
	}

	// Build response with device information
	responses := make([]SessionResponse, 0, len(sessions))
	for _, session := range sessions {
		isCurrent := session.AccessTokenHash == currentTokenHash

		resp := SessionResponse{
			ID:            session.ID,
			IP:            session.ClientIP,
			CreatedAt:     session.CreatedAt,
			AccessExpiry:  session.AccessExpiry,
			RefreshExpiry: session.RefreshExpiry,
			IsCurrent:     isCurrent,
		}

		// Add device information if available
		// Generate device ID from user agent and IP (same as token.go)
		deviceID := generateDeviceID(session.UserAgent, session.ClientIP)
		if device, ok := deviceMap[deviceID]; ok {
			resp.DeviceID = device.DeviceID
			resp.DeviceName = device.DeviceName
			resp.DeviceType = device.DeviceType
			resp.Location = device.Location
			resp.LastActiveAt = device.LastActiveAt
		}

		responses = append(responses, resp)
	}

	response.Success(c, responses)
}

// RevokeSession revokes a specific session
// @Summary Revoke session
// @Description Revoke a specific user session
// @Tags sessions
// @Accept json
// @Produce json
// @Param id path int true "Session ID"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 404 {object} response.Response
// @Failure 500 {object} response.Response
func (h *Handler) RevokeSession(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		response.UnauthorizedWithCode(c, "UNAUTHORIZED", "user not authenticated", nil)
		return
	}

	sessionID := c.Param("id")
	if sessionID == "" {
		response.BadRequestWithCode(c, "INVALID_ID", "session ID is required", nil)
		return
	}

	var session model.UserSession
	if err := h.db.Where("id = ? AND user_id = ?", sessionID, userID).First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFoundWithCode(c, "NOT_FOUND", "session not found", nil)
			return
		}
		logging.Error("failed to query session",
			zap.Error(err),
			zap.String("session_id", sessionID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	if session.RevokedAt.Valid {
		response.Success(c, gin.H{
			"message": "session already revoked",
		})
		return
	}

	// Revoke session
	err := h.db.Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		updates := map[string]interface{}{
			"revoked_at":     sql.NullTime{Time: now, Valid: true},
			"revoked_reason": "revoked by user",
		}

		return tx.Model(&session).Updates(updates).Error
	})

	if err != nil {
		logging.Error("failed to revoke session",
			zap.Error(err),
			zap.Uint64("session_id", session.ID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	_ = h.sessionCache.Set(c.Request.Context(), sessioncache.RevokedSessionMarkerKey(session.ID), []byte("1"), sessioncache.RevokedSessionMarkerTTL(&session))

	response.Success(c, gin.H{
		"message": "session revoked successfully",
	})
}

// RevokeAllSessions revokes all sessions except the current one
// @Summary Revoke all sessions
// @Description Revoke all user sessions except the current one
// @Tags sessions
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 401 {object} response.Response
// @Failure 500 {object} response.Response
func (h *Handler) RevokeAllSessions(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		response.UnauthorizedWithCode(c, "UNAUTHORIZED", "user not authenticated", nil)
		return
	}

	// Get current token to exclude it
	authHeader := c.GetHeader("Authorization")
	var currentToken string
	var hasCurrentToken bool
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		currentToken = authHeader[7:]
		hasCurrentToken = true
	}
	currentTokenHash := hashToken(currentToken)

	var sessions []model.UserSession
	query := h.db.Where("user_id = ? AND revoked_at IS NULL", userID)

	if hasCurrentToken {
		query = query.Where("access_token_hash != ?", currentTokenHash)
	}

	if err := query.Find(&sessions).Error; err != nil {
		logging.Error("failed to query sessions",
			zap.Error(err),
			zap.Uint64("user_id", userID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	if len(sessions) == 0 {
		response.Success(c, gin.H{
			"message":        "no other sessions to revoke",
			"revoked_count":  0,
			"current_active": hasCurrentToken,
		})
		return
	}

	// Revoke all sessions in transaction
	err := h.db.Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		updates := map[string]interface{}{
			"revoked_at":     sql.NullTime{Time: now, Valid: true},
			"revoked_reason": "revoke all sessions",
		}

		revokeQuery := tx.Model(&model.UserSession{}).
			Where("user_id = ? AND revoked_at IS NULL", userID)

		if hasCurrentToken {
			revokeQuery = revokeQuery.Where("access_token_hash != ?", currentTokenHash)
		}

		return revokeQuery.Updates(updates).Error
	})

	if err != nil {
		logging.Error("failed to revoke sessions",
			zap.Error(err),
			zap.Uint64("user_id", userID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	for i := range sessions {
		_ = h.sessionCache.Set(c.Request.Context(), sessioncache.RevokedSessionMarkerKey(sessions[i].ID), []byte("1"), sessioncache.RevokedSessionMarkerTTL(&sessions[i]))
	}

	response.Success(c, gin.H{
		"message":        "all other sessions revoked successfully",
		"revoked_count":  len(sessions),
		"current_active": hasCurrentToken,
	})
}

package platform

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/middleware"
	"paigram/internal/response"
	serviceplatform "paigram/internal/service/platform"
)

type platformReader interface {
	ListEnabledPlatformViews() ([]serviceplatform.PlatformListView, error)
	GetPlatformSchemaView(platformKey string) (*serviceplatform.PlatformSchemaView, error)
	GetPlatformAccountSummary(ctx context.Context, actorType, actorID string, ownerUserID, platformAccountRefID uint64, scopes []string) (map[string]any, error)
}

// Handler manages browser-facing platform registry endpoints.
type Handler struct {
	platformService platformReader
}

// NewHandler constructs a platform handler.
func NewHandler(platformService platformReader) *Handler {
	return &Handler{platformService: platformService}
}

// swagger:route GET /api/v1/me/platforms platform listPlatforms
//
// List enabled platforms.
//
// Returns the enabled platform registry entries that the Web client can manage.
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: platformListResponse
//	500: platformErrorResponse
func (h *Handler) ListPlatforms(c *gin.Context) {
	platforms, err := h.platformService.ListEnabledPlatformViews()
	if err != nil {
		response.InternalServerError(c, "failed to list platforms")
		return
	}

	response.Success(c, platforms)
}

// swagger:route GET /api/v1/me/platforms/{platform}/schema platform getPlatformSchema
//
// Get platform credential schema.
//
// Returns the form schema metadata for a specific enabled platform.
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: platformSchemaEnvelope
//	404: platformErrorResponse
//	500: platformErrorResponse
func (h *Handler) GetPlatformSchema(c *gin.Context) {
	platformKey := strings.TrimSpace(c.Param("platform"))
	if platformKey == "" {
		response.BadRequest(c, "platform is required")
		return
	}

	platform, err := h.platformService.GetPlatformSchemaView(platformKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFound(c, "platform not found")
			return
		}

		response.InternalServerError(c, "failed to load platform schema")
		return
	}

	response.Success(c, platform)
}

// GetPlatformAccountSummary is an unregistered Web/BFF proxy slice for downstream platform summaries.
func (h *Handler) GetPlatformAccountSummary(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	sessionID, ok := middleware.GetSessionID(c)
	if !ok || sessionID == 0 {
		response.Unauthorized(c, "session not found")
		return
	}
	refID, err := strconv.ParseUint(strings.TrimSpace(c.Param("refId")), 10, 64)
	if err != nil || refID == 0 {
		response.BadRequest(c, "invalid platform account ref id")
		return
	}

	summary, err := h.platformService.GetPlatformAccountSummary(c.Request.Context(), "web_user", fmt.Sprintf("session:%d", sessionID), userID, refID, []string{"hoyo.credential.read_meta"})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFound(c, "platform account not found")
			return
		}
		response.InternalServerError(c, "failed to load platform account summary")
		return
	}

	response.Success(c, summary)
}

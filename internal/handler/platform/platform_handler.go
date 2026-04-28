package platform

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/response"
	serviceplatform "paigram/internal/service/platform"
)

type platformReader interface {
	ListEnabledPlatformViews() ([]serviceplatform.PlatformListView, error)
	GetPlatformSchemaView(platformKey string) (*serviceplatform.PlatformSchemaView, error)
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

package adminsystem

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/response"
	serviceplatform "paigram/internal/service/platform"
)

type platformServiceAdmin interface {
	ListPlatformServices(ctx context.Context) ([]serviceplatform.PlatformServiceAdminView, error)
	GetPlatformService(ctx context.Context, id uint64) (*serviceplatform.PlatformServiceAdminView, error)
	GetPlatformServiceConfig(ctx context.Context, id uint64) (*serviceplatform.UpdatePlatformServiceInput, error)
	CreatePlatformService(ctx context.Context, input serviceplatform.CreatePlatformServiceInput) (*serviceplatform.PlatformServiceAdminView, error)
	UpdatePlatformService(ctx context.Context, id uint64, input serviceplatform.UpdatePlatformServiceInput) (*serviceplatform.PlatformServiceAdminView, error)
	DeletePlatformService(ctx context.Context, id uint64) error
	CheckPlatformService(ctx context.Context, id uint64) (*serviceplatform.PlatformServiceAdminView, error)
}

type CreatePlatformServiceRequest struct {
	PlatformKey      string         `json:"platform_key"`
	DisplayName      string         `json:"display_name"`
	ServiceKey       string         `json:"service_key"`
	ServiceAudience  string         `json:"service_audience"`
	DiscoveryType    string         `json:"discovery_type"`
	Endpoint         string         `json:"endpoint"`
	Enabled          bool           `json:"enabled"`
	SupportedActions []string       `json:"supported_actions"`
	CredentialSchema map[string]any `json:"credential_schema"`
}

type UpdatePlatformServiceRequest struct {
	PlatformKey      *string         `json:"platform_key"`
	DisplayName      *string         `json:"display_name"`
	ServiceKey       *string         `json:"service_key"`
	ServiceAudience  *string         `json:"service_audience"`
	DiscoveryType    *string         `json:"discovery_type"`
	Endpoint         *string         `json:"endpoint"`
	Enabled          *bool           `json:"enabled"`
	SupportedActions *[]string       `json:"supported_actions"`
	CredentialSchema *map[string]any `json:"credential_schema"`
}

// PlatformServiceHandler serves the admin system platform registry endpoints.
type PlatformServiceHandler struct {
	service platformServiceAdmin
}

// NewPlatformServiceHandler creates a platform registry handler for /admin/system.
func NewPlatformServiceHandler(service platformServiceAdmin) *PlatformServiceHandler {
	return &PlatformServiceHandler{service: service}
}

// swagger:route GET /api/v1/admin/system/platform-services admin-system listPlatformServices
// List platform services.
func (h *PlatformServiceHandler) ListPlatformServices(c *gin.Context) {
	items, err := h.service.ListPlatformServices(c.Request.Context())
	if err != nil {
		writePlatformServiceError(c, err, "failed to list platform services")
		return
	}

	response.Success(c, items)
}

// swagger:route GET /api/v1/admin/system/platform-services/{id} admin-system getPlatformService
// Get a platform service.
func (h *PlatformServiceHandler) GetPlatformService(c *gin.Context) {
	id, ok := parsePlatformServiceID(c)
	if !ok {
		return
	}

	item, err := h.service.GetPlatformService(c.Request.Context(), id)
	if err != nil {
		writePlatformServiceError(c, err, "failed to get platform service")
		return
	}

	response.Success(c, item)
}

// swagger:route POST /api/v1/admin/system/platform-services admin-system createPlatformService
// Create a platform service.
func (h *PlatformServiceHandler) CreatePlatformService(c *gin.Context) {
	var req CreatePlatformServiceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request payload")
		return
	}

	item, err := h.service.CreatePlatformService(c.Request.Context(), serviceplatform.CreatePlatformServiceInput{
		PlatformKey:      req.PlatformKey,
		DisplayName:      req.DisplayName,
		ServiceKey:       req.ServiceKey,
		ServiceAudience:  req.ServiceAudience,
		DiscoveryType:    req.DiscoveryType,
		Endpoint:         req.Endpoint,
		Enabled:          req.Enabled,
		SupportedActions: req.SupportedActions,
		CredentialSchema: req.CredentialSchema,
	})
	if err != nil {
		writePlatformServiceError(c, err, "failed to create platform service")
		return
	}

	c.JSON(http.StatusCreated, response.Response{Code: http.StatusCreated, Message: "created successfully", Data: item})
}

// swagger:route PATCH /api/v1/admin/system/platform-services/{id} admin-system updatePlatformService
// Update a platform service.
func (h *PlatformServiceHandler) UpdatePlatformService(c *gin.Context) {
	id, ok := parsePlatformServiceID(c)
	if !ok {
		return
	}

	var req UpdatePlatformServiceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request payload")
		return
	}

	current, err := h.service.GetPlatformServiceConfig(c.Request.Context(), id)
	if err != nil {
		writePlatformServiceError(c, err, "failed to get platform service")
		return
	}

	input := *current
	input.SupportedActions = append([]string(nil), current.SupportedActions...)
	input.CredentialSchema = cloneMap(current.CredentialSchema)
	mergePlatformServiceUpdate(&input, req)

	item, err := h.service.UpdatePlatformService(c.Request.Context(), id, input)
	if err != nil {
		writePlatformServiceError(c, err, "failed to update platform service")
		return
	}

	response.Success(c, item)
}

// swagger:route DELETE /api/v1/admin/system/platform-services/{id} admin-system deletePlatformService
// Delete a platform service.
func (h *PlatformServiceHandler) DeletePlatformService(c *gin.Context) {
	id, ok := parsePlatformServiceID(c)
	if !ok {
		return
	}

	if err := h.service.DeletePlatformService(c.Request.Context(), id); err != nil {
		writePlatformServiceError(c, err, "failed to delete platform service")
		return
	}

	response.NoContent(c)
}

// swagger:route POST /api/v1/admin/system/platform-services/{id}/check admin-system checkPlatformService
// Check a platform service.
func (h *PlatformServiceHandler) CheckPlatformService(c *gin.Context) {
	id, ok := parsePlatformServiceID(c)
	if !ok {
		return
	}

	item, err := h.service.CheckPlatformService(c.Request.Context(), id)
	if err != nil {
		writePlatformServiceError(c, err, "failed to check platform service")
		return
	}

	response.Success(c, item)
}

func parsePlatformServiceID(c *gin.Context) (uint64, bool) {
	id, err := strconv.ParseUint(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || id == 0 {
		response.BadRequest(c, "invalid platform service id")
		return 0, false
	}
	return id, true
}

func writePlatformServiceError(c *gin.Context, err error, fallback string) {
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		response.NotFound(c, "platform service not found")
	case errors.Is(err, serviceplatform.ErrPlatformServiceConflict):
		response.Conflict(c, "platform service already exists")
	case errors.Is(err, serviceplatform.ErrPlatformServiceReferenced):
		response.Conflict(c, "platform service is still referenced")
	case errors.Is(err, serviceplatform.ErrInvalidPlatformServiceConfig):
		response.BadRequest(c, "invalid platform service config")
	default:
		response.InternalServerError(c, fallback)
	}
}

func mergePlatformServiceUpdate(input *serviceplatform.UpdatePlatformServiceInput, req UpdatePlatformServiceRequest) {
	if req.PlatformKey != nil {
		input.PlatformKey = *req.PlatformKey
	}
	if req.DisplayName != nil {
		input.DisplayName = *req.DisplayName
	}
	if req.ServiceKey != nil {
		input.ServiceKey = *req.ServiceKey
	}
	if req.ServiceAudience != nil {
		input.ServiceAudience = *req.ServiceAudience
	}
	if req.DiscoveryType != nil {
		input.DiscoveryType = *req.DiscoveryType
	}
	if req.Endpoint != nil {
		input.Endpoint = *req.Endpoint
	}
	if req.Enabled != nil {
		input.Enabled = *req.Enabled
	}
	if req.SupportedActions != nil {
		input.SupportedActions = append(make([]string, 0, len(*req.SupportedActions)), (*req.SupportedActions)...)
	}
	if req.CredentialSchema != nil {
		input.CredentialSchema = cloneMap(*req.CredentialSchema)
	}
}

func cloneMap(src map[string]any) map[string]any {
	if src == nil {
		return map[string]any{}
	}
	dst := make(map[string]any, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

package adminsystem

import (
	"context"
	"errors"

	"github.com/gin-gonic/gin"

	"paigram/internal/middleware"
	"paigram/internal/response"
	servicesystemconfig "paigram/internal/service/systemconfig"
)

// SettingsReader describes the admin system settings dependency.
type SettingsReader interface {
	GetSite(context.Context) (*servicesystemconfig.SettingsView, error)
	PatchSite(context.Context, map[string]any, uint64) (*servicesystemconfig.SettingsView, error)
	GetRegistration(context.Context) (*servicesystemconfig.SettingsView, error)
	PatchRegistration(context.Context, map[string]any, uint64) (*servicesystemconfig.SettingsView, error)
	GetEmail(context.Context) (*servicesystemconfig.SettingsView, error)
	PatchEmail(context.Context, map[string]any, uint64) (*servicesystemconfig.SettingsView, error)
	GetAuthControls(context.Context) (*servicesystemconfig.SettingsView, error)
	PatchAuthControls(context.Context, map[string]any, uint64) (*servicesystemconfig.SettingsView, error)
}

// SettingsHandler serves admin system endpoints.
type SettingsHandler struct {
	service SettingsReader
}

// NewSettingsHandler creates an admin system settings handler.
func NewSettingsHandler(service SettingsReader) *SettingsHandler {
	return &SettingsHandler{service: service}
}

// swagger:route GET /api/v1/admin/system/settings/site admin-system getSystemSiteSettings
// Get grouped site settings.
func (h *SettingsHandler) GetSite(c *gin.Context) {
	view, err := h.service.GetSite(c.Request.Context())
	h.writeView(c, view, err)
}

// swagger:route PATCH /api/v1/admin/system/settings/site admin-system patchSystemSiteSettings
// Update grouped site settings.
func (h *SettingsHandler) PatchSite(c *gin.Context) {
	h.patch(c, h.service.PatchSite)
}

// swagger:route GET /api/v1/admin/system/settings/registration admin-system getSystemRegistrationSettings
// Get grouped registration settings.
func (h *SettingsHandler) GetRegistration(c *gin.Context) {
	view, err := h.service.GetRegistration(c.Request.Context())
	h.writeView(c, view, err)
}

// swagger:route PATCH /api/v1/admin/system/settings/registration admin-system patchSystemRegistrationSettings
// Update grouped registration settings.
func (h *SettingsHandler) PatchRegistration(c *gin.Context) {
	h.patch(c, h.service.PatchRegistration)
}

// swagger:route GET /api/v1/admin/system/settings/email admin-system getSystemEmailSettings
// Get grouped email settings.
func (h *SettingsHandler) GetEmail(c *gin.Context) {
	view, err := h.service.GetEmail(c.Request.Context())
	h.writeView(c, view, err)
}

// swagger:route PATCH /api/v1/admin/system/settings/email admin-system patchSystemEmailSettings
// Update grouped email settings.
func (h *SettingsHandler) PatchEmail(c *gin.Context) {
	h.patch(c, h.service.PatchEmail)
}

// swagger:route GET /api/v1/admin/system/auth-controls admin-system getSystemAuthControls
// Get grouped auth control settings.
func (h *SettingsHandler) GetAuthControls(c *gin.Context) {
	view, err := h.service.GetAuthControls(c.Request.Context())
	h.writeView(c, view, err)
}

// swagger:route PATCH /api/v1/admin/system/auth-controls admin-system patchSystemAuthControls
// Update grouped auth control settings.
func (h *SettingsHandler) PatchAuthControls(c *gin.Context) {
	h.patch(c, h.service.PatchAuthControls)
}

func (h *SettingsHandler) writeView(c *gin.Context, view *servicesystemconfig.SettingsView, err error) {
	if err != nil {
		writeSettingsError(c, err)
		return
	}
	response.Success(c, view)
}

func (h *SettingsHandler) patch(c *gin.Context, fn func(context.Context, map[string]any, uint64) (*servicesystemconfig.SettingsView, error)) {
	var payload map[string]any
	if err := c.ShouldBindJSON(&payload); err != nil {
		response.BadRequest(c, "invalid request payload")
		return
	}
	actorUserID, _ := middleware.GetUserID(c)
	view, err := fn(c.Request.Context(), payload, actorUserID)
	if err != nil {
		writeSettingsError(c, err)
		return
	}
	response.Success(c, view)
}

func writeSettingsError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, servicesystemconfig.ErrInvalidSettingsDomain):
		response.BadRequest(c, "invalid settings domain")
	default:
		response.InternalServerError(c, "failed to load system settings")
	}
}

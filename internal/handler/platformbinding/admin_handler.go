package platformbinding

import (
	"github.com/gin-gonic/gin"

	"paigram/internal/response"
)

// AdminHandler manages admin platform binding routes.
type AdminHandler struct {
	bindingService bindingService
	profileService profileService
	grantService   grantService
}

// NewAdminHandler constructs an admin platform binding handler.
func NewAdminHandler(bindingService bindingService, profileService profileService, grantService grantService) *AdminHandler {
	return &AdminHandler{
		bindingService: bindingService,
		profileService: profileService,
		grantService:   grantService,
	}
}

// swagger:route GET /api/v1/admin/platform-accounts platformbinding-admin listPlatformBindings
// List platform bindings across all users.
func (h *AdminHandler) ListBindings(c *gin.Context) {
	items, err := h.bindingService.ListBindings()
	if err != nil {
		response.InternalServerError(c, "failed to list platform bindings")
		return
	}

	response.Success(c, gin.H{"items": buildAdminBindingViews(items)})
}

// swagger:route GET /api/v1/admin/platform-accounts/{bindingId} platformbinding-admin getPlatformBinding
// Get one platform binding across all users.
func (h *AdminHandler) GetBinding(c *gin.Context) {
	bindingID, ok := parseBindingID(c)
	if !ok {
		return
	}

	binding, err := h.bindingService.GetBindingByID(bindingID)
	if err != nil {
		writeBindingError(c, err, "failed to get platform binding")
		return
	}

	response.Success(c, buildAdminBindingView(binding))
}

// swagger:route GET /api/v1/admin/platform-accounts/{bindingId}/profiles platformbinding-admin listPlatformBindingProfiles
// List platform binding profiles across all users.
func (h *AdminHandler) ListProfiles(c *gin.Context) {
	bindingID, ok := parseBindingID(c)
	if !ok {
		return
	}

	if _, err := h.bindingService.GetBindingByID(bindingID); err != nil {
		writeBindingError(c, err, "failed to get platform binding")
		return
	}

	items, err := h.profileService.ListProfiles(bindingID)
	if err != nil {
		writeBindingError(c, err, "failed to list platform binding profiles")
		return
	}

	response.Success(c, gin.H{"items": buildProfileViews(items)})
}

// swagger:route GET /api/v1/admin/platform-accounts/{bindingId}/consumer-grants platformbinding-admin listPlatformBindingConsumerGrants
// List platform binding consumer grants across all users.
func (h *AdminHandler) ListConsumerGrants(c *gin.Context) {
	bindingID, ok := parseBindingID(c)
	if !ok {
		return
	}

	if _, err := h.bindingService.GetBindingByID(bindingID); err != nil {
		writeBindingError(c, err, "failed to get platform binding")
		return
	}

	items, err := h.grantService.ListGrants(bindingID)
	if err != nil {
		writeBindingError(c, err, "failed to list platform binding consumer grants")
		return
	}

	response.Success(c, gin.H{"items": buildGrantViews(items)})
}

// swagger:route PUT /api/v1/admin/platform-accounts/{bindingId}/consumer-grants/{consumer} platformbinding-admin putPlatformBindingConsumerGrant
// Upsert or revoke one platform binding consumer grant across all users.
func (h *AdminHandler) PutConsumerGrant(c *gin.Context) {
	bindingID, ok := parseBindingID(c)
	if !ok {
		return
	}

	if _, err := h.bindingService.GetBindingByID(bindingID); err != nil {
		writeBindingError(c, err, "failed to get platform binding")
		return
	}

	userID, ok := currentUserID(c)
	if !ok {
		return
	}

	grant, ok := putConsumerGrant(c, h.grantService, bindingID, userID)
	if !ok {
		return
	}

	response.Success(c, buildGrantView(grant))
}

// swagger:route POST /api/v1/admin/platform-accounts/{bindingId}/refresh platformbinding-admin refreshPlatformBinding
// Mark one platform binding as requiring refresh.
func (h *AdminHandler) RefreshBinding(c *gin.Context) {
	bindingID, ok := parseBindingID(c)
	if !ok {
		return
	}

	binding, err := h.bindingService.RefreshBinding(bindingID)
	if err != nil {
		writeBindingError(c, err, "failed to refresh platform binding")
		return
	}

	response.Success(c, buildAdminBindingView(binding))
}

// swagger:route DELETE /api/v1/admin/platform-accounts/{bindingId} platformbinding-admin deletePlatformBinding
// Delete one platform binding across all users.
func (h *AdminHandler) DeleteBinding(c *gin.Context) {
	bindingID, ok := parseBindingID(c)
	if !ok {
		return
	}

	if _, err := h.bindingService.DeleteBinding(bindingID); err != nil {
		writeBindingError(c, err, "failed to delete platform binding")
		return
	}

	response.NoContent(c)
}

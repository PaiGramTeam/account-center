package platformbinding

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"paigram/internal/response"
	serviceplatformbinding "paigram/internal/service/platformbinding"
)

// AdminHandler manages admin platform binding routes.
type AdminHandler struct {
	bindingService        bindingService
	profileService        profileService
	grantService          grantService
	orchestrationService  orchestrationService
	runtimeSummaryService runtimeSummaryService
}

// NewAdminHandler constructs an admin platform binding handler.
func NewAdminHandler(bindingService bindingService, profileService profileService, grantService grantService, orchestrationService orchestrationService, runtimeSummaryService runtimeSummaryService) *AdminHandler {
	return &AdminHandler{
		bindingService:        bindingService,
		profileService:        profileService,
		grantService:          grantService,
		orchestrationService:  orchestrationService,
		runtimeSummaryService: runtimeSummaryService,
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

	binding, err := h.orchestrationService.RefreshBindingAsAdmin(c.Request.Context(), bindingID)
	if err != nil {
		writeBindingError(c, err, "failed to refresh platform binding")
		return
	}

	response.Success(c, buildAdminBindingView(binding))
}

// swagger:route PUT /api/v1/admin/platform-accounts/{bindingId}/credential platformbinding-admin putPlatformBindingCredential
// Update one platform binding credential across all users via orchestration.
func (h *AdminHandler) PutCredential(c *gin.Context) {
	bindingID, ok := parseBindingID(c)
	if !ok {
		return
	}

	adminUserID, ok := currentUserID(c)
	if !ok {
		return
	}

	payload, ok := readCredentialPayload(c)
	if !ok {
		return
	}

	summary, err := h.orchestrationService.PutCredentialAsAdmin(c.Request.Context(), serviceplatformbinding.PutCredentialInput{
		BindingID:          bindingID,
		ActorType:          "admin",
		ActorID:            "admin:" + strconv.FormatUint(adminUserID, 10),
		RequestedByAdminID: adminUserID,
		CredentialPayload:  payload,
	})
	if err != nil {
		writeBindingError(c, err, "failed to update platform credential")
		return
	}

	response.Success(c, summary)
}

// swagger:route GET /api/v1/admin/platform-accounts/{bindingId}/runtime-summary platformbinding-admin getPlatformBindingRuntimeSummary
// Get one platform binding runtime summary across all users.
func (h *AdminHandler) GetRuntimeSummary(c *gin.Context) {
	bindingID, ok := parseBindingID(c)
	if !ok {
		return
	}

	summary, err := h.runtimeSummaryService.GetRuntimeSummaryAsAdmin(c.Request.Context(), bindingID)
	if err != nil {
		writeBindingError(c, err, "failed to get runtime summary")
		return
	}

	response.Success(c, summary)
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

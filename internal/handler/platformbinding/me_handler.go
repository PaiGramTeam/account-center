package platformbinding

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"paigram/internal/middleware"
	"paigram/internal/model"
	"paigram/internal/response"
	serviceplatformbinding "paigram/internal/service/platformbinding"
)

type bindingService interface {
	CreateBinding(input serviceplatformbinding.CreateBindingInput) (*model.PlatformAccountBinding, error)
	GetBindingByID(bindingID uint64) (*model.PlatformAccountBinding, error)
	GetBindingForOwner(ownerUserID, bindingID uint64) (*model.PlatformAccountBinding, error)
	ListBindings(params serviceplatformbinding.ListParams) ([]model.PlatformAccountBinding, int64, error)
	ListBindingsByOwner(ownerUserID uint64, params serviceplatformbinding.ListParams) ([]model.PlatformAccountBinding, int64, error)
	UpdateBindingForOwner(ownerUserID, bindingID uint64, input serviceplatformbinding.UpdateBindingInput) (*model.PlatformAccountBinding, error)
	DeleteBinding(bindingID uint64) (*model.PlatformAccountBinding, error)
	DeleteBindingForOwner(ownerUserID, bindingID uint64) (*model.PlatformAccountBinding, error)
}

type profileService interface {
	ListProfiles(bindingID uint64, params serviceplatformbinding.ListParams) ([]model.PlatformAccountProfile, int64, error)
	ListProfilesForOwner(ownerUserID, bindingID uint64, params serviceplatformbinding.ListParams) ([]model.PlatformAccountProfile, int64, error)
}

type grantService interface {
	ListGrants(bindingID uint64, params serviceplatformbinding.ListParams) ([]model.ConsumerGrant, int64, error)
	ListGrantsForOwner(ownerUserID, bindingID uint64, params serviceplatformbinding.ListParams) ([]model.ConsumerGrant, int64, error)
	UpsertGrant(input serviceplatformbinding.UpsertGrantInput) (*model.ConsumerGrant, bool, error)
	UpsertGrantForOwner(ownerUserID uint64, input serviceplatformbinding.UpsertGrantInput) (*model.ConsumerGrant, bool, error)
	RevokeGrant(input serviceplatformbinding.RevokeGrantInput) (*model.ConsumerGrant, error)
	RevokeGrantForOwner(ownerUserID uint64, input serviceplatformbinding.RevokeGrantInput) (*model.ConsumerGrant, error)
}

type orchestrationService interface {
	CreateBindingForOwner(ctx context.Context, input serviceplatformbinding.CreateAndBindInput) (*model.PlatformAccountBinding, error)
	PutCredentialForOwner(ctx context.Context, input serviceplatformbinding.PutCredentialInput) (*serviceplatformbinding.RuntimeSummary, error)
	PutCredentialAsAdmin(ctx context.Context, input serviceplatformbinding.PutCredentialInput) (*serviceplatformbinding.RuntimeSummary, error)
	RefreshBindingForOwner(ctx context.Context, ownerUserID, bindingID uint64) (*model.PlatformAccountBinding, error)
	RefreshBindingAsAdmin(ctx context.Context, bindingID uint64) (*model.PlatformAccountBinding, error)
	SetPrimaryProfileForOwner(ctx context.Context, ownerUserID, bindingID, profileID uint64, actorID string) (*model.PlatformAccountBinding, error)
	DeleteBindingForOwner(ctx context.Context, ownerUserID, bindingID uint64) error
	DeleteBindingAsAdmin(ctx context.Context, bindingID, adminUserID uint64) error
}

type runtimeSummaryService interface {
	GetRuntimeSummary(ctx context.Context, ownerUserID, bindingID uint64) (*serviceplatformbinding.RuntimeSummary, error)
	GetRuntimeSummaryAsAdmin(ctx context.Context, bindingID uint64) (*serviceplatformbinding.RuntimeSummary, error)
}

type CreateBindingRequest struct {
	Platform          string          `json:"platform"`
	DisplayName       string          `json:"display_name"`
	CredentialPayload json.RawMessage `json:"credential_payload"`
}

type PutConsumerGrantRequest struct {
	Enabled *bool `json:"enabled"`
}

type PatchBindingRequest struct {
	DisplayName        *string `json:"display_name"`
	PlatformServiceKey *string `json:"platform_service_key"`
}

type PatchPrimaryProfileRequest struct {
	ProfileID *uint64 `json:"profile_id"`
}

// MeHandler manages self-service platform binding routes.
type MeHandler struct {
	bindingService        bindingService
	profileService        profileService
	grantService          grantService
	orchestrationService  orchestrationService
	runtimeSummaryService runtimeSummaryService
}

// NewMeHandler constructs a self-service platform binding handler.
func NewMeHandler(bindingService bindingService, profileService profileService, grantService grantService, orchestrationService orchestrationService, runtimeSummaryService runtimeSummaryService) *MeHandler {
	return &MeHandler{
		bindingService:        bindingService,
		profileService:        profileService,
		grantService:          grantService,
		orchestrationService:  orchestrationService,
		runtimeSummaryService: runtimeSummaryService,
	}
}

// swagger:route GET /api/v1/me/platform-accounts platformbinding-me listMyPlatformBindings
// List current user's platform bindings.
func (h *MeHandler) ListBindings(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		return
	}

	page, pageSize := parseListParams(c)
	items, total, err := h.bindingService.ListBindingsByOwner(userID, serviceplatformbinding.ListParams{Page: page, PageSize: pageSize})
	if err != nil {
		response.InternalServerError(c, "failed to list platform bindings")
		return
	}

	response.SuccessWithPagination(c, buildMeBindingViews(items), total, page, pageSize)
}

// swagger:route POST /api/v1/me/platform-accounts platformbinding-me createMyPlatformBinding
// Create a current-user platform binding draft and bind it immediately.
func (h *MeHandler) CreateBinding(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		return
	}

	var req CreateBindingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request payload")
		return
	}
	if len(req.CredentialPayload) == 0 || string(req.CredentialPayload) == "null" {
		response.BadRequest(c, "credential_payload is required")
		return
	}

	actorID := actorIDFromSession(c, userID)
	binding, err := h.orchestrationService.CreateBindingForOwner(c.Request.Context(), serviceplatformbinding.CreateAndBindInput{
		OwnerUserID:       userID,
		Platform:          strings.TrimSpace(req.Platform),
		DisplayName:       strings.TrimSpace(req.DisplayName),
		ActorType:         "user",
		ActorID:           actorID,
		CredentialPayload: req.CredentialPayload,
	})
	if err != nil {
		writeBindingError(c, err, "failed to create platform binding")
		return
	}

	c.JSON(http.StatusCreated, response.Response{
		Code:    http.StatusCreated,
		Message: "created successfully",
		Data:    buildMeBindingView(binding),
	})
}

// swagger:route GET /api/v1/me/platform-accounts/{bindingId} platformbinding-me getMyPlatformBinding
// Get one current-user platform binding.
func (h *MeHandler) GetBinding(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		return
	}

	bindingID, ok := parseBindingID(c)
	if !ok {
		return
	}

	binding, err := h.bindingService.GetBindingForOwner(userID, bindingID)
	if err != nil {
		writeBindingError(c, err, "failed to get platform binding")
		return
	}

	response.Success(c, buildMeBindingView(binding))
}

// swagger:route PATCH /api/v1/me/platform-accounts/{bindingId} platformbinding-me patchMyPlatformBinding
// Update one current-user platform binding.
func (h *MeHandler) PatchBinding(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		return
	}

	bindingID, ok := parseBindingID(c)
	if !ok {
		return
	}

	var req PatchBindingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request payload")
		return
	}
	if req.DisplayName != nil {
		value := strings.TrimSpace(*req.DisplayName)
		if value == "" {
			response.BadRequest(c, "display_name is required")
			return
		}
		req.DisplayName = &value
	}
	if req.PlatformServiceKey != nil {
		value := strings.TrimSpace(*req.PlatformServiceKey)
		if value == "" {
			response.BadRequest(c, "platform_service_key is required")
			return
		}
		req.PlatformServiceKey = &value
	}

	binding, err := h.bindingService.UpdateBindingForOwner(userID, bindingID, serviceplatformbinding.UpdateBindingInput{
		DisplayName:        req.DisplayName,
		PlatformServiceKey: req.PlatformServiceKey,
	})
	if err != nil {
		writeBindingError(c, err, "failed to update platform binding")
		return
	}

	response.Success(c, buildMeBindingView(binding))
}

// swagger:route DELETE /api/v1/me/platform-accounts/{bindingId} platformbinding-me deleteMyPlatformBinding
// Delete one current-user platform binding.
func (h *MeHandler) DeleteBinding(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		return
	}

	bindingID, ok := parseBindingID(c)
	if !ok {
		return
	}

	if err := h.orchestrationService.DeleteBindingForOwner(c.Request.Context(), userID, bindingID); err != nil {
		writeBindingError(c, err, "failed to delete platform binding")
		return
	}

	response.NoContent(c)
}

// swagger:route POST /api/v1/me/platform-accounts/{bindingId}/refresh platformbinding-me refreshMyPlatformBinding
// Mark one current-user platform binding as requiring refresh.
func (h *MeHandler) RefreshBinding(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		return
	}

	bindingID, ok := parseBindingID(c)
	if !ok {
		return
	}

	binding, err := h.orchestrationService.RefreshBindingForOwner(c.Request.Context(), userID, bindingID)
	if err != nil {
		writeBindingError(c, err, "failed to refresh platform binding")
		return
	}

	response.Success(c, buildMeBindingView(binding))
}

// swagger:route PUT /api/v1/me/platform-accounts/{bindingId}/credential platformbinding-me putMyPlatformBindingCredential
// Update one current-user platform binding credential via orchestration.
func (h *MeHandler) PutCredential(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		return
	}

	bindingID, ok := parseBindingID(c)
	if !ok {
		return
	}

	payload, ok := readCredentialPayload(c)
	if !ok {
		return
	}

	actorID := actorIDFromSession(c, userID)
	summary, err := h.orchestrationService.PutCredentialForOwner(c.Request.Context(), serviceplatformbinding.PutCredentialInput{
		OwnerUserID:       userID,
		BindingID:         bindingID,
		ActorType:         "user",
		ActorID:           actorID,
		CredentialPayload: payload,
	})
	if err != nil {
		writeBindingError(c, err, "failed to update platform credential")
		return
	}

	response.Success(c, summary)
}

// swagger:route GET /api/v1/me/platform-accounts/{bindingId}/runtime-summary platformbinding-me getMyPlatformBindingRuntimeSummary
// Get one current-user platform binding runtime summary.
func (h *MeHandler) GetRuntimeSummary(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		return
	}

	bindingID, ok := parseBindingID(c)
	if !ok {
		return
	}

	summary, err := h.runtimeSummaryService.GetRuntimeSummary(c.Request.Context(), userID, bindingID)
	if err != nil {
		writeBindingError(c, err, "failed to get runtime summary")
		return
	}

	response.Success(c, summary)
}

// swagger:route PATCH /api/v1/me/platform-accounts/{bindingId}/primary-profile platformbinding-me patchMyPlatformBindingPrimaryProfile
// Update one current-user platform binding primary profile.
func (h *MeHandler) PatchPrimaryProfile(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		return
	}

	bindingID, ok := parseBindingID(c)
	if !ok {
		return
	}

	var req PatchPrimaryProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request payload")
		return
	}
	if req.ProfileID == nil || *req.ProfileID == 0 {
		response.BadRequest(c, "profile_id is required")
		return
	}

	binding, err := h.orchestrationService.SetPrimaryProfileForOwner(c.Request.Context(), userID, bindingID, *req.ProfileID, actorIDFromSession(c, userID))
	if err != nil {
		writeBindingError(c, err, "failed to update primary profile")
		return
	}

	response.Success(c, buildMeBindingView(binding))
}

// swagger:route GET /api/v1/me/platform-accounts/{bindingId}/profiles platformbinding-me listMyPlatformBindingProfiles
// List current-user platform binding profiles.
func (h *MeHandler) ListProfiles(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		return
	}

	bindingID, ok := parseBindingID(c)
	if !ok {
		return
	}

	page, pageSize := parseListParams(c)
	items, total, err := h.profileService.ListProfilesForOwner(userID, bindingID, serviceplatformbinding.ListParams{Page: page, PageSize: pageSize})
	if err != nil {
		writeBindingError(c, err, "failed to list platform binding profiles")
		return
	}

	response.SuccessWithPagination(c, buildProfileViews(items), total, page, pageSize)
}

// swagger:route GET /api/v1/me/platform-accounts/{bindingId}/consumer-grants platformbinding-me listMyPlatformBindingConsumerGrants
// List current-user platform binding consumer grants.
func (h *MeHandler) ListConsumerGrants(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		return
	}

	bindingID, ok := parseBindingID(c)
	if !ok {
		return
	}

	page, pageSize := parseListParams(c)
	items, total, err := h.grantService.ListGrantsForOwner(userID, bindingID, serviceplatformbinding.ListParams{Page: page, PageSize: pageSize})
	if err != nil {
		writeBindingError(c, err, "failed to list platform binding consumer grants")
		return
	}

	response.SuccessWithPagination(c, buildGrantViews(items), total, page, pageSize)
}

func parseListParams(c *gin.Context) (int, int) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	return page, pageSize
}

// swagger:route PUT /api/v1/me/platform-accounts/{bindingId}/consumer-grants/{consumer} platformbinding-me putMyPlatformBindingConsumerGrant
// Upsert or idempotently revoke one registry-controlled current-user platform binding consumer grant.
func (h *MeHandler) PutConsumerGrant(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		return
	}

	bindingID, ok := parseBindingID(c)
	if !ok {
		return
	}

	grant, ok := putConsumerGrantForOwner(c, h.grantService, userID, bindingID)
	if !ok {
		return
	}

	response.Success(c, buildGrantView(grant))
}

func currentUserID(c *gin.Context) (uint64, bool) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return 0, false
	}

	return userID, true
}

func parseBindingID(c *gin.Context) (uint64, bool) {
	param := strings.TrimSpace(c.Param("bindingId"))
	bindingID, err := strconv.ParseUint(param, 10, 64)
	if err != nil || bindingID == 0 {
		response.BadRequest(c, "invalid binding id")
		return 0, false
	}

	return bindingID, true
}

func putConsumerGrant(c *gin.Context, grantService grantService, bindingID, actorUserID uint64) (*model.ConsumerGrant, bool) {
	req, ok := readPutConsumerGrantRequest(c)
	if !ok {
		return nil, false
	}

	consumer, ok := parseConsumer(c)
	if !ok {
		return nil, false
	}

	grantedBy := sql.NullInt64{Int64: int64(actorUserID), Valid: true}
	if *req.Enabled {
		grant, _, err := grantService.UpsertGrant(serviceplatformbinding.UpsertGrantInput{
			BindingID: bindingID,
			Consumer:  consumer,
			GrantedBy: grantedBy,
			GrantedAt: time.Now().UTC(),
		})
		if err != nil {
			writeBindingError(c, err, "failed to update consumer grant")
			return nil, false
		}

		return grant, true
	}

	grant, err := grantService.RevokeGrant(serviceplatformbinding.RevokeGrantInput{
		BindingID: bindingID,
		Consumer:  consumer,
		RevokedAt: time.Now().UTC(),
	})
	if err != nil {
		writeBindingError(c, err, "failed to update consumer grant")
		return nil, false
	}

	return grant, true
}

func parseConsumer(c *gin.Context) (string, bool) {
	consumer := strings.TrimSpace(c.Param("consumer"))
	if consumer == "" {
		response.BadRequest(c, "consumer is required")
		return "", false
	}

	return consumer, true
}

func putConsumerGrantForOwner(c *gin.Context, grantService grantService, ownerUserID, bindingID uint64) (*model.ConsumerGrant, bool) {
	req, ok := readPutConsumerGrantRequest(c)
	if !ok {
		return nil, false
	}

	consumer, ok := parseConsumer(c)
	if !ok {
		return nil, false
	}

	grantedBy := sql.NullInt64{Int64: int64(ownerUserID), Valid: true}
	if *req.Enabled {
		grant, _, err := grantService.UpsertGrantForOwner(ownerUserID, serviceplatformbinding.UpsertGrantInput{
			BindingID: bindingID,
			Consumer:  consumer,
			GrantedBy: grantedBy,
			GrantedAt: time.Now().UTC(),
		})
		if err != nil {
			writeBindingError(c, err, "failed to update consumer grant")
			return nil, false
		}

		return grant, true
	}

	grant, err := grantService.RevokeGrantForOwner(ownerUserID, serviceplatformbinding.RevokeGrantInput{
		BindingID: bindingID,
		Consumer:  consumer,
		RevokedAt: time.Now().UTC(),
	})
	if err != nil {
		writeBindingError(c, err, "failed to update consumer grant")
		return nil, false
	}

	return grant, true
}

func readPutConsumerGrantRequest(c *gin.Context) (*PutConsumerGrantRequest, bool) {
	var req PutConsumerGrantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request payload")
		return nil, false
	}
	if req.Enabled == nil {
		response.BadRequest(c, "enabled is required")
		return nil, false
	}

	return &req, true
}

func writeBindingError(c *gin.Context, err error, fallback string) {
	switch {
	case errors.Is(err, serviceplatformbinding.ErrBindingNotFound):
		response.NotFound(c, "platform binding not found")
	case errors.Is(err, serviceplatformbinding.ErrGrantNotFound):
		response.NotFound(c, "consumer grant not found")
	case errors.Is(err, serviceplatformbinding.ErrBindingAlreadyOwned):
		response.Conflict(c, "platform binding already owned by another user")
	case errors.Is(err, serviceplatformbinding.ErrCredentialValidationFailed):
		response.Error(c, http.StatusUnprocessableEntity, "platform credential validation failed")
	case errors.Is(err, serviceplatformbinding.ErrConsumerNotSupported):
		response.BadRequest(c, "consumer is not supported")
	case errors.Is(err, serviceplatformbinding.ErrBindingRuntimeSummaryNotReady):
		response.Conflict(c, "platform binding runtime summary is not ready")
	case errors.Is(err, serviceplatformbinding.ErrPrimaryProfileNotOwned):
		response.Error(c, http.StatusUnprocessableEntity, "primary profile must belong to platform binding")
	default:
		if serviceplatformbinding.IsExecutionPlaneUnavailableError(err) {
			response.Error(c, http.StatusServiceUnavailable, "platform service unavailable")
			return
		}
		response.InternalServerError(c, fallback)
	}
}

func buildMeBindingViews(items []model.PlatformAccountBinding) []gin.H {
	views := make([]gin.H, 0, len(items))
	for _, item := range items {
		views = append(views, buildMeBindingView(&item))
	}

	return views
}

func buildAdminBindingViews(items []model.PlatformAccountBinding) []gin.H {
	views := make([]gin.H, 0, len(items))
	for _, item := range items {
		views = append(views, buildAdminBindingView(&item))
	}

	return views
}

func buildMeBindingView(binding *model.PlatformAccountBinding) gin.H {
	return gin.H{
		"id":                    binding.ID,
		"platform":              binding.Platform,
		"external_account_key":  nullableString(binding.ExternalAccountKey),
		"platform_service_key":  binding.PlatformServiceKey,
		"display_name":          binding.DisplayName,
		"status":                binding.Status,
		"status_reason_code":    binding.StatusReasonCode,
		"status_reason_message": binding.StatusReasonMessage,
		"primary_profile_id":    nullableInt64(binding.PrimaryProfileID),
		"last_validated_at":     nullableTime(binding.LastValidatedAt),
		"last_synced_at":        nullableTime(binding.LastSyncedAt),
		"created_at":            binding.CreatedAt,
		"updated_at":            binding.UpdatedAt,
	}
}

func buildAdminBindingView(binding *model.PlatformAccountBinding) gin.H {
	view := buildMeBindingView(binding)
	view["owner_user_id"] = binding.OwnerUserID
	return view
}

func buildProfileViews(items []model.PlatformAccountProfile) []gin.H {
	views := make([]gin.H, 0, len(items))
	for _, item := range items {
		views = append(views, gin.H{
			"id":                   item.ID,
			"binding_id":           item.BindingID,
			"platform_profile_key": item.PlatformProfileKey,
			"game_biz":             item.GameBiz,
			"region":               item.Region,
			"player_uid":           item.PlayerUID,
			"nickname":             item.Nickname,
			"level":                nullableInt64(item.Level),
			"is_primary":           item.IsPrimary,
			"source_updated_at":    nullableTime(item.SourceUpdatedAt),
			"created_at":           item.CreatedAt,
			"updated_at":           item.UpdatedAt,
		})
	}

	return views
}

func buildGrantViews(items []model.ConsumerGrant) []gin.H {
	views := make([]gin.H, 0, len(items))
	for _, item := range items {
		views = append(views, buildGrantView(&item))
	}

	return views
}

func buildGrantView(item *model.ConsumerGrant) gin.H {
	return gin.H{
		"id":         item.ID,
		"binding_id": item.BindingID,
		"consumer":   item.Consumer,
		"status":     item.Status,
		"granted_by": nullableInt64(item.GrantedBy),
		"granted_at": item.GrantedAt,
		"revoked_at": nullableTime(item.RevokedAt),
		"created_at": item.CreatedAt,
		"updated_at": item.UpdatedAt,
	}
}

func nullableInt64(value sql.NullInt64) any {
	if !value.Valid {
		return nil
	}

	return value.Int64
}

func nullableTime(value sql.NullTime) any {
	if !value.Valid {
		return nil
	}

	return value.Time
}

func nullableString(value sql.NullString) any {
	if !value.Valid {
		return nil
	}

	return value.String
}

func normalizeExternalAccountKey(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}

	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return sql.NullString{}
	}

	return sql.NullString{String: trimmed, Valid: true}
}

func readCredentialPayload(c *gin.Context) (json.RawMessage, bool) {
	var payload json.RawMessage
	if err := c.ShouldBindJSON(&payload); err != nil || len(payload) == 0 {
		response.BadRequest(c, "invalid request payload")
		return nil, false
	}

	return payload, true
}

func actorIDFromSession(c *gin.Context, userID uint64) string {
	if sessionID, ok := middleware.GetSessionID(c); ok && sessionID != 0 {
		return "session:" + strconv.FormatUint(sessionID, 10)
	}

	return "user:" + strconv.FormatUint(userID, 10)
}

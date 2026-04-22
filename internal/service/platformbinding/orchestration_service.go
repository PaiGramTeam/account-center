package platformbinding

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
	"paigram/internal/model"
	serviceaudit "paigram/internal/service/audit"
	serviceplatform "paigram/internal/service/platform"
)

type orchestrationBindingReader interface {
	CreateBinding(input CreateBindingInput) (*model.PlatformAccountBinding, error)
	DeleteBinding(bindingID uint64) (*model.PlatformAccountBinding, error)
	GetBindingByID(bindingID uint64) (*model.PlatformAccountBinding, error)
	GetBindingForOwner(ownerUserID, bindingID uint64) (*model.PlatformAccountBinding, error)
	PersistRuntimeSummary(bindingID uint64, summary RuntimeSummary) (*model.PlatformAccountBinding, error)
	UpdateBindingStatus(bindingID uint64, status model.PlatformAccountBindingStatus) (*model.PlatformAccountBinding, error)
	UpdateBindingFailure(bindingID uint64, status model.PlatformAccountBindingStatus, reasonCode, reasonMessage string) (*model.PlatformAccountBinding, error)
}

type orchestrationProfileSyncer interface {
	SyncProfiles(input SyncProfilesInput) ([]model.PlatformAccountProfile, error)
	DeleteProfiles(bindingID uint64) error
	GetProfile(bindingID, profileID uint64) (*model.PlatformAccountProfile, error)
	SetPrimaryProfileForOwner(ownerUserID, bindingID uint64, profileID *uint64) (*model.PlatformAccountBinding, error)
}

type orchestrationGrantCleaner interface {
	DeleteGrants(bindingID uint64) error
}

type orchestrationPlatformService interface {
	GetEnabledPlatform(platformKey string) (*model.PlatformService, error)
	IssueBindingScopedTicket(actorType, actorID string, binding *model.PlatformAccountBinding, scopes []string) (string, time.Time, error)
	ConfirmBindingPrimaryProfile(ctx context.Context, actorType, actorID string, binding *model.PlatformAccountBinding, playerID string) error
}

type credentialGateway interface {
	PutCredential(ctx context.Context, endpoint, ticket string, binding *model.PlatformAccountBinding, payload json.RawMessage) (map[string]any, error)
	RefreshCredential(ctx context.Context, endpoint, ticket string, binding *model.PlatformAccountBinding) error
	DeleteCredential(ctx context.Context, endpoint, ticket string, binding *model.PlatformAccountBinding) error
}

type OrchestrationService struct {
	bindingReader   orchestrationBindingReader
	platformService orchestrationPlatformService
	gateway         credentialGateway
	profileSyncer   orchestrationProfileSyncer
	grantCleaner    orchestrationGrantCleaner
	auditWriter     orchestrationAuditWriter
}

type orchestrationAuditWriter interface {
	Record(context.Context, serviceaudit.WriteInput) error
}

func NewOrchestrationService(bindingReader orchestrationBindingReader, platformService orchestrationPlatformService, gateway credentialGateway, dependencies ...any) *OrchestrationService {
	service := &OrchestrationService{bindingReader: bindingReader, platformService: platformService, gateway: gateway}
	for _, dependency := range dependencies {
		switch typed := dependency.(type) {
		case orchestrationProfileSyncer:
			service.profileSyncer = typed
		case orchestrationGrantCleaner:
			service.grantCleaner = typed
		case orchestrationAuditWriter:
			service.auditWriter = typed
		}
	}
	return service
}

func (s *OrchestrationService) CreateBindingForOwner(ctx context.Context, input CreateAndBindInput) (*model.PlatformAccountBinding, error) {
	platformRow, err := s.platformService.GetEnabledPlatform(input.Platform)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, serviceplatform.ErrPlatformServiceUnavailable
		}
		return nil, err
	}

	binding, err := s.bindingReader.CreateBinding(CreateBindingInput{
		OwnerUserID:        input.OwnerUserID,
		Platform:           input.Platform,
		PlatformServiceKey: platformRow.ServiceKey,
		DisplayName:        input.DisplayName,
	})
	if err != nil {
		s.recordBindingAudit(ctx, nil, "binding_create", "failure", reasonCode(err), &input.OwnerUserID, input.ActorType, input.ActorID, map[string]any{"platform": input.Platform})
		return nil, err
	}

	_, updatedBinding, err := s.putCredential(ctx, binding, PutCredentialInput{
		OwnerUserID:       input.OwnerUserID,
		BindingID:         binding.ID,
		ActorType:         input.ActorType,
		ActorID:           input.ActorID,
		CredentialPayload: input.CredentialPayload,
	})
	if err != nil {
		s.recordBindingAudit(ctx, binding, "binding_create", "failure", reasonCode(err), &input.OwnerUserID, input.ActorType, input.ActorID, map[string]any{"platform": input.Platform})
		if updatedBinding != nil {
			if updatedBinding.ID != binding.ID {
				if _, deleteErr := s.bindingReader.DeleteBinding(binding.ID); deleteErr != nil {
					return nil, deleteErr
				}
			}
			return updatedBinding, nil
		}
		return nil, err
	}
	if updatedBinding != nil {
		s.recordBindingAudit(ctx, updatedBinding, "binding_create", "success", "", &input.OwnerUserID, input.ActorType, input.ActorID, map[string]any{"platform": input.Platform})
		if updatedBinding.ID != binding.ID {
			if _, deleteErr := s.bindingReader.DeleteBinding(binding.ID); deleteErr != nil {
				return nil, deleteErr
			}
		}
		return updatedBinding, nil
	}
	resolvedBinding, err := s.bindingReader.GetBindingForOwner(input.OwnerUserID, binding.ID)
	if err == nil {
		s.recordBindingAudit(ctx, resolvedBinding, "binding_create", "success", "", &input.OwnerUserID, input.ActorType, input.ActorID, map[string]any{"platform": input.Platform})
	}
	return resolvedBinding, err
}

func (s *OrchestrationService) PutCredentialForOwner(ctx context.Context, input PutCredentialInput) (*RuntimeSummary, error) {
	binding, err := s.bindingReader.GetBindingForOwner(input.OwnerUserID, input.BindingID)
	if err != nil {
		return nil, err
	}

	summary, _, err := s.putCredential(ctx, binding, input)
	if err != nil {
		s.recordBindingAudit(ctx, binding, "credential_update", "failure", reasonCode(err), uint64Ptr(binding.OwnerUserID), input.ActorType, input.ActorID, nil)
		if errors.Is(err, ErrCredentialValidationFailed) {
			s.recordBindingAudit(ctx, binding, "platform_validation_failure", "failure", reasonCode(err), uint64Ptr(binding.OwnerUserID), input.ActorType, input.ActorID, nil)
		}
		return summary, err
	}
	s.recordBindingAudit(ctx, binding, "credential_update", "success", "", uint64Ptr(binding.OwnerUserID), input.ActorType, input.ActorID, nil)
	return summary, err
}

func (s *OrchestrationService) PutCredentialAsAdmin(ctx context.Context, input PutCredentialInput) (*RuntimeSummary, error) {
	binding, err := s.bindingReader.GetBindingByID(input.BindingID)
	if err != nil {
		return nil, err
	}

	summary, _, err := s.putCredential(ctx, binding, input)
	if err != nil {
		s.recordBindingAudit(ctx, binding, "credential_update", "failure", reasonCode(err), uint64Ptr(binding.OwnerUserID), input.ActorType, input.ActorID, nil)
		if errors.Is(err, ErrCredentialValidationFailed) {
			s.recordBindingAudit(ctx, binding, "platform_validation_failure", "failure", reasonCode(err), uint64Ptr(binding.OwnerUserID), input.ActorType, input.ActorID, nil)
		}
		return summary, err
	}
	s.recordBindingAudit(ctx, binding, "credential_update", "success", "", uint64Ptr(binding.OwnerUserID), input.ActorType, input.ActorID, nil)
	return summary, err
}

func (s *OrchestrationService) RefreshBindingForOwner(ctx context.Context, ownerUserID, bindingID uint64) (*model.PlatformAccountBinding, error) {
	binding, err := s.bindingReader.GetBindingForOwner(ownerUserID, bindingID)
	if err != nil {
		return nil, err
	}

	updated, err := s.refreshBinding(ctx, binding, "user", "binding-refresh")
	if err != nil {
		s.recordBindingAudit(ctx, binding, "binding_refresh", "failure", reasonCode(err), uint64Ptr(binding.OwnerUserID), "user", "binding-refresh", nil)
		return nil, err
	}
	s.recordBindingAudit(ctx, updated, "binding_refresh", "success", "", uint64Ptr(binding.OwnerUserID), "user", "binding-refresh", nil)
	return updated, nil
}

func (s *OrchestrationService) RefreshBindingAsAdmin(ctx context.Context, bindingID, adminUserID uint64) (*model.PlatformAccountBinding, error) {
	binding, err := s.bindingReader.GetBindingByID(bindingID)
	if err != nil {
		return nil, err
	}

	actorID := "admin:" + strconv.FormatUint(adminUserID, 10)
	updated, err := s.refreshBinding(ctx, binding, "admin", actorID)
	if err != nil {
		s.recordBindingAudit(ctx, binding, "binding_refresh", "failure", reasonCode(err), uint64Ptr(binding.OwnerUserID), "admin", actorID, nil)
		return nil, err
	}
	s.recordBindingAudit(ctx, updated, "binding_refresh", "success", "", uint64Ptr(binding.OwnerUserID), "admin", actorID, nil)
	return updated, nil
}

func (s *OrchestrationService) DeleteBindingForOwner(ctx context.Context, ownerUserID, bindingID uint64) error {
	binding, err := s.bindingReader.GetBindingForOwner(ownerUserID, bindingID)
	if err != nil {
		return err
	}

	err = s.deleteBinding(ctx, binding, "user", "binding-delete")
	if err != nil {
		s.recordBindingAudit(ctx, binding, "binding_delete", "failure", reasonCode(err), uint64Ptr(binding.OwnerUserID), "user", "binding-delete", nil)
		return err
	}
	s.recordBindingAudit(ctx, binding, "binding_delete", "success", "", uint64Ptr(binding.OwnerUserID), "user", "binding-delete", nil)
	return nil
}

func (s *OrchestrationService) DeleteBindingAsAdmin(ctx context.Context, bindingID, adminUserID uint64) error {
	binding, err := s.bindingReader.GetBindingByID(bindingID)
	if err != nil {
		return err
	}

	actorID := "admin:" + strconv.FormatUint(adminUserID, 10)
	err = s.deleteBinding(ctx, binding, "admin", actorID)
	if err != nil {
		s.recordBindingAudit(ctx, binding, "binding_delete", "failure", reasonCode(err), uint64Ptr(binding.OwnerUserID), "admin", actorID, nil)
		return err
	}
	s.recordBindingAudit(ctx, binding, "binding_delete", "success", "", uint64Ptr(binding.OwnerUserID), "admin", actorID, nil)
	return nil
}

func (s *OrchestrationService) RepairDeleteFailedBinding(ctx context.Context, bindingID uint64) error {
	binding, err := s.bindingReader.GetBindingByID(bindingID)
	if err != nil {
		return err
	}
	if binding == nil || binding.Status != model.PlatformAccountBindingStatusDeleteFailed {
		return nil
	}
	return s.deleteBinding(ctx, binding, "consumer", "platform-binding-delete-repair")
}

func (s *OrchestrationService) SetPrimaryProfileForOwner(ctx context.Context, ownerUserID, bindingID, profileID uint64, actorID string) (*model.PlatformAccountBinding, error) {
	binding, err := s.bindingReader.GetBindingForOwner(ownerUserID, bindingID)
	if err != nil {
		return nil, err
	}
	if binding == nil || !binding.ExternalAccountKey.Valid || binding.ExternalAccountKey.String == "" {
		return nil, ErrBindingRuntimeSummaryNotReady
	}
	if s.profileSyncer == nil {
		return nil, ErrPrimaryProfileNotOwned
	}

	profile, err := s.profileSyncer.GetProfile(binding.ID, profileID)
	if err != nil {
		return nil, err
	}
	if profile == nil || profile.PlayerUID == "" {
		return nil, ErrPrimaryProfileNotOwned
	}

	if err := s.platformService.ConfirmBindingPrimaryProfile(ctx, "user", actorID, binding, profile.PlayerUID); err != nil {
		if IsCredentialValidationError(err) {
			s.recordBindingAudit(ctx, binding, "platform_validation_failure", "failure", "credential_validation_failed", uint64Ptr(binding.OwnerUserID), "user", actorID, map[string]any{"profile_id": profile.ID})
			s.recordBindingAudit(ctx, binding, "primary_profile_change", "failure", "credential_validation_failed", uint64Ptr(binding.OwnerUserID), "user", actorID, map[string]any{"profile_id": profile.ID})
			return nil, fmt.Errorf("%w: %v", ErrCredentialValidationFailed, err)
		}
		s.recordBindingAudit(ctx, binding, "primary_profile_change", "failure", reasonCode(err), uint64Ptr(binding.OwnerUserID), "user", actorID, map[string]any{"profile_id": profile.ID})
		return nil, err
	}

	updatedBinding, err := s.profileSyncer.SetPrimaryProfileForOwner(ownerUserID, binding.ID, &profile.ID)
	if err != nil {
		s.recordBindingAudit(ctx, binding, "primary_profile_change", "failure", reasonCode(err), uint64Ptr(binding.OwnerUserID), "user", actorID, map[string]any{"profile_id": profile.ID})
		return nil, err
	}
	s.recordBindingAudit(ctx, updatedBinding, "primary_profile_change", "success", "", uint64Ptr(binding.OwnerUserID), "user", actorID, map[string]any{"profile_id": profile.ID})
	return updatedBinding, nil
}

func (s *OrchestrationService) refreshBinding(ctx context.Context, binding *model.PlatformAccountBinding, actorType, actorID string) (*model.PlatformAccountBinding, error) {
	if s.gateway == nil {
		return nil, ErrCredentialGatewayUnavailable
	}

	platformRow, err := s.platformService.GetEnabledPlatform(binding.Platform)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, serviceplatform.ErrPlatformServiceUnavailable
		}
		return nil, err
	}

	ticket, _, err := s.platformService.IssueBindingScopedTicket(actorType, actorID, binding, []string{"mihomo.credential.refresh"})
	if err != nil {
		return nil, err
	}

	if err := s.gateway.RefreshCredential(ctx, platformRow.Endpoint, ticket, binding); err != nil {
		return nil, err
	}

	return s.bindingReader.UpdateBindingStatus(binding.ID, model.PlatformAccountBindingStatusRefreshRequired)
}

func (s *OrchestrationService) deleteBinding(ctx context.Context, binding *model.PlatformAccountBinding, actorType, actorID string) error {
	if binding == nil {
		return ErrBindingNotFound
	}
	wasCleanupFailed := binding.Status == model.PlatformAccountBindingStatusDeleteFailed && binding.StatusReasonCode == "control_plane_cleanup_failed"
	if _, err := s.bindingReader.UpdateBindingStatus(binding.ID, model.PlatformAccountBindingStatusDeleting); err != nil {
		return err
	}
	if wasCleanupFailed {
		_, err := s.bindingReader.DeleteBinding(binding.ID)
		if err != nil {
			return s.markDeleteFailed(binding.ID, err, "control_plane_cleanup_failed")
		}
		return nil
	}

	if !binding.ExternalAccountKey.Valid || binding.ExternalAccountKey.String == "" {
		_, err := s.bindingReader.DeleteBinding(binding.ID)
		if err != nil {
			return s.markDeleteFailed(binding.ID, err, "control_plane_cleanup_failed")
		}
		return nil
	}
	if s.gateway == nil {
		return s.markDeleteFailed(binding.ID, ErrCredentialGatewayUnavailable, "credential_delete_failed")
	}

	platformRow, err := s.platformService.GetEnabledPlatform(binding.Platform)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = serviceplatform.ErrPlatformServiceUnavailable
		}
		return s.markDeleteFailed(binding.ID, err, "credential_delete_failed")
	}

	ticket, _, err := s.platformService.IssueBindingScopedTicket(actorType, actorID, binding, []string{"mihomo.credential.delete"})
	if err != nil {
		return s.markDeleteFailed(binding.ID, err, "credential_delete_failed")
	}

	if err := s.gateway.DeleteCredential(ctx, platformRow.Endpoint, ticket, binding); err != nil {
		return s.markDeleteFailed(binding.ID, err, "credential_delete_failed")
	}

	_, err = s.bindingReader.DeleteBinding(binding.ID)
	if err != nil {
		return s.markDeleteFailed(binding.ID, err, "control_plane_cleanup_failed")
	}
	return nil
}

func (s *OrchestrationService) markDeleteFailed(bindingID uint64, err error, reasonCode string) error {
	if err == nil {
		return nil
	}
	_, _ = s.bindingReader.UpdateBindingFailure(bindingID, model.PlatformAccountBindingStatusDeleteFailed, reasonCode, err.Error())
	return err
}

func (s *OrchestrationService) putCredential(ctx context.Context, binding *model.PlatformAccountBinding, input PutCredentialInput) (*RuntimeSummary, *model.PlatformAccountBinding, error) {
	if s.gateway == nil {
		return nil, nil, ErrCredentialGatewayUnavailable
	}

	platformRow, err := s.platformService.GetEnabledPlatform(binding.Platform)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, serviceplatform.ErrPlatformServiceUnavailable
		}
		return nil, nil, err
	}

	scopes := []string{"mihomo.credential.bind"}
	if binding.ExternalAccountKey.Valid {
		scopes = []string{"mihomo.credential.update"}
	}

	ticket, _, err := s.platformService.IssueBindingScopedTicket(input.ActorType, input.ActorID, binding, scopes)
	if err != nil {
		return nil, nil, err
	}

	summary, err := s.gateway.PutCredential(ctx, platformRow.Endpoint, ticket, binding, input.CredentialPayload)
	if err != nil {
		return nil, nil, s.handlePutCredentialError(binding, err)
	}

	runtimeSummary, err := decodeRuntimeSummary(summary)
	if err != nil {
		return nil, nil, err
	}
	updatedBinding, err := s.bindingReader.PersistRuntimeSummary(binding.ID, *runtimeSummary)
	if err != nil {
		if errors.Is(err, ErrBindingAlreadyOwned) {
			cleanupErr := s.compensateDeleteCredential(ctx, binding, runtimeSummary.PlatformAccountID, input.ActorType, input.ActorID, platformRow.Endpoint)
			if cleanupErr != nil {
				_, _ = s.bindingReader.UpdateBindingFailure(binding.ID, model.PlatformAccountBindingStatusDeleteFailed, "compensation_delete_failed", cleanupErr.Error())
				return nil, nil, fmt.Errorf("%w: cleanup failed: %v", ErrBindingAlreadyOwned, cleanupErr)
			}
			_, _ = s.bindingReader.UpdateBindingFailure(binding.ID, model.PlatformAccountBindingStatusCredentialInvalid, "duplicate_owner", "platform binding already owned by another user")
		}
		return nil, nil, err
	}
	if err := s.syncProfiles(binding, updatedBinding, runtimeSummary); err != nil {
		return runtimeSummary, updatedBinding, err
	}

	return runtimeSummary, updatedBinding, nil
}

func (s *OrchestrationService) handlePutCredentialError(binding *model.PlatformAccountBinding, err error) error {
	if !IsCredentialValidationError(err) {
		return err
	}
	if binding != nil {
		_, _ = s.bindingReader.UpdateBindingFailure(binding.ID, model.PlatformAccountBindingStatusCredentialInvalid, "credential_validation_failed", err.Error())
	}
	return fmt.Errorf("%w: %v", ErrCredentialValidationFailed, err)
}

func (s *OrchestrationService) compensateDeleteCredential(ctx context.Context, binding *model.PlatformAccountBinding, resolvedAccountKey, actorType, actorID, endpoint string) error {
	if s.gateway == nil {
		return ErrCredentialGatewayUnavailable
	}
	resolvedBinding := binding
	if binding != nil && resolvedAccountKey != "" {
		clone := *binding
		clone.ExternalAccountKey = sql.NullString{String: resolvedAccountKey, Valid: true}
		resolvedBinding = &clone
	}

	ticket, _, err := s.platformService.IssueBindingScopedTicket(actorType, actorID, resolvedBinding, []string{"mihomo.credential.delete"})
	if err != nil {
		return err
	}

	return s.gateway.DeleteCredential(ctx, endpoint, ticket, resolvedBinding)
}

func (s *OrchestrationService) syncProfiles(binding, updatedBinding *model.PlatformAccountBinding, summary *RuntimeSummary) error {
	if s.profileSyncer == nil || binding == nil || summary == nil || len(summary.Profiles) == 0 {
		return nil
	}
	bindingID := binding.ID
	if updatedBinding != nil {
		bindingID = updatedBinding.ID
	}
	profiles := buildProfileProjectionInputs(binding.Platform, summary.Profiles)
	if len(profiles) == 0 {
		return nil
	}
	_, err := s.profileSyncer.SyncProfiles(SyncProfilesInput{
		BindingID: bindingID,
		Profiles:  profiles,
		SyncedAt:  time.Now().UTC(),
	})
	return err
}

func buildProfileProjectionInputs(platform string, rawProfiles []map[string]any) []ProfileProjectionInput {
	profiles := make([]ProfileProjectionInput, 0, len(rawProfiles))
	for _, raw := range rawProfiles {
		playerUID := mapString(raw["player_id"])
		gameBiz := mapString(raw["game_biz"])
		region := mapString(raw["region"])
		nickname := mapString(raw["nickname"])
		platformProfileKey := derivePlatformProfileKey(platform, raw, playerUID)
		if platformProfileKey == "" || playerUID == "" || gameBiz == "" || region == "" || nickname == "" {
			continue
		}
		profiles = append(profiles, ProfileProjectionInput{
			PlatformProfileKey: platformProfileKey,
			GameBiz:            gameBiz,
			Region:             region,
			PlayerUID:          playerUID,
			Nickname:           nickname,
			Level:              nullableLevel(raw["level"]),
			IsPrimary:          mapBool(raw["is_default"]),
		})
	}
	return profiles
}

func derivePlatformProfileKey(platform string, raw map[string]any, playerUID string) string {
	if id := mapUint64(raw["id"]); id != 0 {
		return platform + ":" + strconv.FormatUint(id, 10)
	}
	if playerUID != "" {
		return platform + ":" + playerUID
	}
	return ""
}

func mapString(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func mapBool(value any) bool {
	flag, ok := value.(bool)
	return ok && flag
}

func mapUint64(value any) uint64 {
	switch v := value.(type) {
	case uint64:
		return v
	case uint32:
		return uint64(v)
	case int:
		if v > 0 {
			return uint64(v)
		}
	case int32:
		if v > 0 {
			return uint64(v)
		}
	case int64:
		if v > 0 {
			return uint64(v)
		}
	case float64:
		if v > 0 {
			return uint64(v)
		}
	}
	return 0
}

func nullableLevel(value any) sql.NullInt64 {
	switch v := value.(type) {
	case int:
		return sql.NullInt64{Int64: int64(v), Valid: true}
	case int32:
		return sql.NullInt64{Int64: int64(v), Valid: true}
	case int64:
		return sql.NullInt64{Int64: v, Valid: true}
	case float64:
		return sql.NullInt64{Int64: int64(v), Valid: true}
	}
	return sql.NullInt64{}
}

type unavailableCredentialGateway struct{}

func (unavailableCredentialGateway) PutCredential(context.Context, string, string, *model.PlatformAccountBinding, json.RawMessage) (map[string]any, error) {
	return nil, ErrCredentialGatewayUnavailable
}

func (unavailableCredentialGateway) RefreshCredential(context.Context, string, string, *model.PlatformAccountBinding) error {
	return ErrCredentialGatewayUnavailable
}

func (unavailableCredentialGateway) DeleteCredential(context.Context, string, string, *model.PlatformAccountBinding) error {
	return ErrCredentialGatewayUnavailable
}

func (s *OrchestrationService) recordBindingAudit(ctx context.Context, binding *model.PlatformAccountBinding, action, result, reason string, ownerUserID *uint64, actorType, actorID string, metadata map[string]any) {
	if s == nil || s.auditWriter == nil {
		return
	}
	var bindingID *uint64
	targetID := ""
	if binding != nil {
		bindingID = &binding.ID
		targetID = strconv.FormatUint(binding.ID, 10)
		if ownerUserID == nil && binding.OwnerUserID != 0 {
			ownerUserID = uint64Ptr(binding.OwnerUserID)
		}
	}
	payload := map[string]any{"actor_id": actorID}
	for key, value := range metadata {
		payload[key] = value
	}
	_ = s.auditWriter.Record(ctx, serviceaudit.WriteInput{
		Category:    "platform_binding",
		ActorType:   actorType,
		ActorUserID: actorUserIDFromAuditContext(actorType, actorID, ownerUserID),
		Action:      action,
		TargetType:  "binding",
		TargetID:    targetID,
		BindingID:   bindingID,
		OwnerUserID: ownerUserID,
		Result:      result,
		ReasonCode:  reason,
		Metadata:    payload,
	})
}

func actorUserIDFromAuditContext(actorType, actorID string, ownerUserID *uint64) *uint64 {
	switch actorType {
	case "user":
		if ownerUserID != nil {
			return ownerUserID
		}
	case "admin":
		const prefix = "admin:"
		if strings.HasPrefix(actorID, prefix) {
			if value, err := strconv.ParseUint(strings.TrimPrefix(actorID, prefix), 10, 64); err == nil && value != 0 {
				return &value
			}
		}
	}
	return nil
}

func reasonCode(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, ErrCredentialValidationFailed):
		return "credential_validation_failed"
	case errors.Is(err, ErrCredentialGatewayUnavailable):
		return "credential_gateway_unavailable"
	case errors.Is(err, serviceplatform.ErrPlatformServiceUnavailable):
		return "platform_service_unavailable"
	case errors.Is(err, ErrBindingNotFound):
		return "binding_not_found"
	default:
		return "operation_failed"
	}
}

func uint64Ptr(value uint64) *uint64 {
	if value == 0 {
		return nil
	}
	return &value
}

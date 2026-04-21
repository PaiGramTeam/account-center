package platformbinding

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"gorm.io/gorm"
	"paigram/internal/model"
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
}

type orchestrationPlatformService interface {
	GetEnabledPlatform(platformKey string) (*model.PlatformService, error)
	IssueBindingScopedTicket(actorType, actorID string, binding *model.PlatformAccountBinding, scopes []string) (string, time.Time, error)
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
}

func NewOrchestrationService(bindingReader orchestrationBindingReader, platformService orchestrationPlatformService, gateway credentialGateway, profileSyncer ...orchestrationProfileSyncer) *OrchestrationService {
	service := &OrchestrationService{bindingReader: bindingReader, platformService: platformService, gateway: gateway}
	if len(profileSyncer) > 0 {
		service.profileSyncer = profileSyncer[0]
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
		if updatedBinding.ID != binding.ID {
			if _, deleteErr := s.bindingReader.DeleteBinding(binding.ID); deleteErr != nil {
				return nil, deleteErr
			}
		}
		return updatedBinding, nil
	}

	return s.bindingReader.GetBindingForOwner(input.OwnerUserID, binding.ID)
}

func (s *OrchestrationService) PutCredentialForOwner(ctx context.Context, input PutCredentialInput) (*RuntimeSummary, error) {
	binding, err := s.bindingReader.GetBindingForOwner(input.OwnerUserID, input.BindingID)
	if err != nil {
		return nil, err
	}

	summary, _, err := s.putCredential(ctx, binding, input)
	return summary, err
}

func (s *OrchestrationService) PutCredentialAsAdmin(ctx context.Context, input PutCredentialInput) (*RuntimeSummary, error) {
	binding, err := s.bindingReader.GetBindingByID(input.BindingID)
	if err != nil {
		return nil, err
	}

	summary, _, err := s.putCredential(ctx, binding, input)
	return summary, err
}

func (s *OrchestrationService) RefreshBindingForOwner(ctx context.Context, ownerUserID, bindingID uint64) (*model.PlatformAccountBinding, error) {
	binding, err := s.bindingReader.GetBindingForOwner(ownerUserID, bindingID)
	if err != nil {
		return nil, err
	}

	return s.refreshBinding(ctx, binding, "user", "binding-refresh")
}

func (s *OrchestrationService) RefreshBindingAsAdmin(ctx context.Context, bindingID uint64) (*model.PlatformAccountBinding, error) {
	binding, err := s.bindingReader.GetBindingByID(bindingID)
	if err != nil {
		return nil, err
	}

	return s.refreshBinding(ctx, binding, "admin", "binding-refresh-admin")
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

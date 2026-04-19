package platformbinding

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"paigram/internal/model"
	serviceplatform "paigram/internal/service/platform"
)

type orchestrationBindingReader interface {
	GetBindingByID(bindingID uint64) (*model.PlatformAccountBinding, error)
	GetBindingForOwner(ownerUserID, bindingID uint64) (*model.PlatformAccountBinding, error)
	PersistRuntimeSummary(bindingID uint64, summary RuntimeSummary) (*model.PlatformAccountBinding, error)
	UpdateBindingStatus(bindingID uint64, status model.PlatformAccountBindingStatus) (*model.PlatformAccountBinding, error)
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
}

func NewOrchestrationService(bindingReader orchestrationBindingReader, platformService orchestrationPlatformService, gateway credentialGateway) *OrchestrationService {
	return &OrchestrationService{bindingReader: bindingReader, platformService: platformService, gateway: gateway}
}

func (s *OrchestrationService) PutCredentialForOwner(ctx context.Context, input PutCredentialInput) (*RuntimeSummary, error) {
	binding, err := s.bindingReader.GetBindingForOwner(input.OwnerUserID, input.BindingID)
	if err != nil {
		return nil, err
	}

	return s.putCredential(ctx, binding, input)
}

func (s *OrchestrationService) PutCredentialAsAdmin(ctx context.Context, input PutCredentialInput) (*RuntimeSummary, error) {
	binding, err := s.bindingReader.GetBindingByID(input.BindingID)
	if err != nil {
		return nil, err
	}

	return s.putCredential(ctx, binding, input)
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

func (s *OrchestrationService) putCredential(ctx context.Context, binding *model.PlatformAccountBinding, input PutCredentialInput) (*RuntimeSummary, error) {
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

	scopes := []string{"mihomo.credential.bind"}
	if binding.ExternalAccountKey.Valid {
		scopes = []string{"mihomo.credential.update"}
	}

	ticket, _, err := s.platformService.IssueBindingScopedTicket(input.ActorType, input.ActorID, binding, scopes)
	if err != nil {
		return nil, err
	}

	summary, err := s.gateway.PutCredential(ctx, platformRow.Endpoint, ticket, binding, input.CredentialPayload)
	if err != nil {
		return nil, err
	}

	runtimeSummary, err := decodeRuntimeSummary(summary)
	if err != nil {
		return nil, err
	}
	if _, err := s.bindingReader.PersistRuntimeSummary(binding.ID, *runtimeSummary); err != nil {
		if errors.Is(err, ErrBindingAlreadyOwned) {
			cleanupErr := s.compensateDeleteCredential(ctx, binding, runtimeSummary.PlatformAccountID, input.ActorType, input.ActorID, platformRow.Endpoint)
			if cleanupErr != nil {
				return nil, fmt.Errorf("%w: cleanup failed: %v", ErrBindingAlreadyOwned, cleanupErr)
			}
		}
		return nil, err
	}

	return runtimeSummary, nil
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

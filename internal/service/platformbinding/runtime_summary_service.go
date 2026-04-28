package platformbinding

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"paigram/internal/model"
	serviceplatform "paigram/internal/service/platform"
)

type runtimeSummaryPlatformService interface {
	GetBindingRuntimeSummary(ctx context.Context, actorType, actorID string, binding *model.PlatformAccountBinding, scopes []string) (map[string]any, error)
}

type runtimeSummaryBindingReader interface {
	GetBindingByID(bindingID uint64) (*model.PlatformAccountBinding, error)
	GetBindingForOwner(ownerUserID, bindingID uint64) (*model.PlatformAccountBinding, error)
	PersistRuntimeSummary(bindingID uint64, summary RuntimeSummary) (*model.PlatformAccountBinding, error)
}

type runtimeSummaryProfileSyncer interface {
	SyncProfiles(input SyncProfilesInput) ([]model.PlatformAccountProfile, error)
}

type RuntimeSummaryService struct {
	platformService runtimeSummaryPlatformService
	bindingReader   runtimeSummaryBindingReader
	profileSyncer   runtimeSummaryProfileSyncer
}

func NewRuntimeSummaryService(platformService runtimeSummaryPlatformService, bindingReader runtimeSummaryBindingReader, dependencies ...any) *RuntimeSummaryService {
	service := &RuntimeSummaryService{platformService: platformService, bindingReader: bindingReader}
	for _, dependency := range dependencies {
		syncer, ok := dependency.(runtimeSummaryProfileSyncer)
		if ok {
			service.profileSyncer = syncer
		}
	}
	return service
}

func (s *RuntimeSummaryService) GetRuntimeSummary(ctx context.Context, ownerUserID, bindingID uint64) (*RuntimeSummary, error) {
	binding, err := s.bindingReader.GetBindingForOwner(ownerUserID, bindingID)
	if err != nil {
		return nil, err
	}
	if !binding.ExternalAccountKey.Valid {
		return nil, ErrBindingRuntimeSummaryNotReady
	}

	summary, err := s.platformService.GetBindingRuntimeSummary(ctx, "user", "binding-runtime-summary", binding, []string{"mihomo.credential.read_meta"})
	if err != nil {
		return nil, normalizeRuntimeSummaryError(err)
	}

	return decodeRuntimeSummary(summary)
}

func (s *RuntimeSummaryService) GetRuntimeSummaryAsAdmin(ctx context.Context, bindingID uint64) (*RuntimeSummary, error) {
	binding, err := s.bindingReader.GetBindingByID(bindingID)
	if err != nil {
		return nil, err
	}
	if !binding.ExternalAccountKey.Valid {
		return nil, ErrBindingRuntimeSummaryNotReady
	}

	summary, err := s.platformService.GetBindingRuntimeSummary(ctx, "admin", "binding-runtime-summary-admin", binding, []string{"mihomo.credential.read_meta"})
	if err != nil {
		return nil, normalizeRuntimeSummaryError(err)
	}

	return decodeRuntimeSummary(summary)
}

func (s *RuntimeSummaryService) RepairProjection(ctx context.Context, bindingID uint64) (*model.PlatformAccountBinding, error) {
	binding, err := s.bindingReader.GetBindingByID(bindingID)
	if err != nil {
		return nil, err
	}
	if !binding.ExternalAccountKey.Valid || binding.ExternalAccountKey.String == "" {
		return nil, ErrBindingRuntimeSummaryNotReady
	}

	summary, err := s.platformService.GetBindingRuntimeSummary(ctx, "consumer", "platform-binding-reconcile", binding, []string{"mihomo.credential.read_meta"})
	if err != nil {
		return nil, normalizeRuntimeSummaryError(err)
	}

	runtimeSummary, err := decodeRuntimeSummary(summary)
	if err != nil {
		return nil, err
	}

	updatedBinding, err := s.bindingReader.PersistRuntimeSummary(binding.ID, *runtimeSummary)
	if err != nil {
		return nil, err
	}
	if s.profileSyncer == nil {
		return updatedBinding, nil
	}

	_, err = s.profileSyncer.SyncProfiles(SyncProfilesInput{
		BindingID: binding.ID,
		Profiles:  buildProfileProjectionInputs(binding.Platform, runtimeSummary.Profiles),
		SyncedAt:  time.Now().UTC(),
	})
	if err != nil {
		return updatedBinding, err
	}
	return updatedBinding, nil
}

func decodeRuntimeSummary(raw map[string]any) (*RuntimeSummary, error) {
	payload, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}

	var summary RuntimeSummary
	if err := json.Unmarshal(payload, &summary); err != nil {
		return nil, err
	}

	return &summary, nil
}

func normalizeRuntimeSummaryError(err error) error {
	if err == nil {
		return nil
	}
	if IsExecutionPlaneUnavailableError(err) {
		if errors.Is(err, serviceplatform.ErrPlatformServiceUnavailable) {
			return err
		}
		return serviceplatform.ErrPlatformSummaryProxyUnavailable
	}
	return err
}

package platformbinding

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"gorm.io/gorm"

	"paigram/internal/model"
	serviceplatform "paigram/internal/service/platform"
)

type fakeRuntimeSummaryBindingReader struct {
	binding          *model.PlatformAccountBinding
	ownerBinding     *model.PlatformAccountBinding
	err              error
	deleteErr        error
	ownerID          uint64
	id               uint64
	deletedID        uint64
	updated          bool
	updatedStatus    model.PlatformAccountBindingStatus
	updatedReason    string
	updatedMessage   string
	persistedSummary *RuntimeSummary
}

func (f *fakeRuntimeSummaryBindingReader) GetBindingByID(bindingID uint64) (*model.PlatformAccountBinding, error) {
	f.id = bindingID
	if f.err != nil {
		return nil, f.err
	}
	return f.binding, nil
}

func (f *fakeRuntimeSummaryBindingReader) GetBindingForOwner(ownerUserID, bindingID uint64) (*model.PlatformAccountBinding, error) {
	f.ownerID = ownerUserID
	f.id = bindingID
	if f.err != nil {
		return nil, f.err
	}
	if f.ownerBinding != nil && f.ownerBinding.ID == bindingID {
		return f.ownerBinding, nil
	}
	return f.binding, nil
}

func (f *fakeRuntimeSummaryBindingReader) UpdateBindingStatus(bindingID uint64, status model.PlatformAccountBindingStatus) (*model.PlatformAccountBinding, error) {
	f.updated = true
	f.updatedStatus = status
	if f.binding != nil {
		f.binding.Status = status
	}
	return f.binding, nil
}

func (f *fakeRuntimeSummaryBindingReader) UpdateBindingFailure(bindingID uint64, status model.PlatformAccountBindingStatus, reasonCode, reasonMessage string) (*model.PlatformAccountBinding, error) {
	f.id = bindingID
	f.updated = true
	f.updatedStatus = status
	f.updatedReason = reasonCode
	f.updatedMessage = reasonMessage
	if f.binding != nil {
		f.binding.Status = status
		f.binding.StatusReasonCode = reasonCode
		f.binding.StatusReasonMessage = reasonMessage
	}
	return f.binding, nil
}

func (f *fakeRuntimeSummaryBindingReader) CreateBinding(input CreateBindingInput) (*model.PlatformAccountBinding, error) {
	f.binding = &model.PlatformAccountBinding{
		ID:                 404,
		OwnerUserID:        input.OwnerUserID,
		Platform:           input.Platform,
		PlatformServiceKey: input.PlatformServiceKey,
		DisplayName:        input.DisplayName,
		Status:             model.PlatformAccountBindingStatusPendingBind,
	}
	return f.binding, nil
}

func (f *fakeRuntimeSummaryBindingReader) DeleteBinding(bindingID uint64) (*model.PlatformAccountBinding, error) {
	f.deletedID = bindingID
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	if f.binding != nil && f.binding.ID == bindingID {
		deleted := *f.binding
		deleted.Status = model.PlatformAccountBindingStatusDeleted
		return &deleted, nil
	}
	return nil, nil
}

func (f *fakeRuntimeSummaryBindingReader) PersistRuntimeSummary(bindingID uint64, summary RuntimeSummary) (*model.PlatformAccountBinding, error) {
	f.id = bindingID
	f.persistedSummary = &summary
	if f.binding != nil {
		if summary.PlatformAccountID != "" {
			f.binding.ExternalAccountKey = sql.NullString{String: summary.PlatformAccountID, Valid: true}
		}
		f.binding.Status = model.PlatformAccountBindingStatusActive
	}
	return f.binding, nil
}

type fakeOrchestrationPlatformService struct {
	platform              *model.PlatformService
	err                   error
	ticket                string
	ticketErr             error
	lastScope             []string
	confirmCalled         bool
	confirmActorType      string
	confirmActorID        string
	confirmBinding        *model.PlatformAccountBinding
	confirmPlayerID       string
	confirmPrimaryProfile error
}

func (f *fakeOrchestrationPlatformService) GetEnabledPlatform(string) (*model.PlatformService, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.platform, nil
}

func (f *fakeOrchestrationPlatformService) IssueBindingScopedTicket(actorType, actorID string, binding *model.PlatformAccountBinding, scopes []string) (string, time.Time, error) {
	f.lastScope = append([]string(nil), scopes...)
	if f.ticketErr != nil {
		return "", time.Time{}, f.ticketErr
	}
	return f.ticket, time.Time{}, nil
}

func (f *fakeOrchestrationPlatformService) ConfirmBindingPrimaryProfile(ctx context.Context, actorType, actorID string, binding *model.PlatformAccountBinding, playerID string) error {
	f.confirmCalled = true
	f.confirmActorType = actorType
	f.confirmActorID = actorID
	f.confirmBinding = binding
	f.confirmPlayerID = playerID
	return f.confirmPrimaryProfile
}

type fakeRefreshGateway struct {
	err      error
	called   bool
	endpoint string
	ticket   string
	binding  *model.PlatformAccountBinding
}

func (f *fakeRefreshGateway) PutCredential(context.Context, string, string, *model.PlatformAccountBinding, json.RawMessage) (map[string]any, error) {
	panic("unexpected call")
}

func (f *fakeRefreshGateway) RefreshCredential(ctx context.Context, endpoint, ticket string, binding *model.PlatformAccountBinding) error {
	f.called = true
	f.endpoint = endpoint
	f.ticket = ticket
	f.binding = binding
	return f.err
}

func (f *fakeRefreshGateway) DeleteCredential(context.Context, string, string, *model.PlatformAccountBinding) error {
	panic("unexpected call")
}

type fakeRuntimeSummaryPlatformService struct {
	summary       map[string]any
	err           error
	lastBinding   *model.PlatformAccountBinding
	lastActorType string
	lastActorID   string
	lastScopes    []string
	callCount     int
}

type fakeCredentialGateway struct {
	summary          map[string]any
	err              error
	called           bool
	deleteCalled     bool
	deleteCallCount  int
	deleteErr        error
	deleteEndpoint   string
	deleteTicket     string
	deleteBindingID  uint64
	deleteAccountKey sql.NullString
}

type fakeProfileSyncer struct {
	called bool
	input  SyncProfilesInput
	err    error

	profile           *model.PlatformAccountProfile
	getProfileErr     error
	lastLookupBinding uint64
	lastLookupProfile uint64
	setPrimaryCalled  bool
	setPrimaryOwnerID uint64
	setPrimaryBinding uint64
	setPrimaryProfile *uint64
	setPrimaryResult  *model.PlatformAccountBinding
	setPrimaryErr     error

	deleteCalled    bool
	deleteBindingID uint64
	deleteErr       error
}

func (f *fakeProfileSyncer) SyncProfiles(input SyncProfilesInput) ([]model.PlatformAccountProfile, error) {
	f.called = true
	f.input = input
	if f.err != nil {
		return nil, f.err
	}
	return nil, nil
}

func (f *fakeProfileSyncer) DeleteProfiles(bindingID uint64) error {
	f.deleteCalled = true
	f.deleteBindingID = bindingID
	return f.deleteErr
}

func (f *fakeProfileSyncer) GetProfile(bindingID, profileID uint64) (*model.PlatformAccountProfile, error) {
	f.lastLookupBinding = bindingID
	f.lastLookupProfile = profileID
	if f.getProfileErr != nil {
		return nil, f.getProfileErr
	}
	return f.profile, nil
}

func (f *fakeProfileSyncer) SetPrimaryProfileForOwner(ownerUserID, bindingID uint64, profileID *uint64) (*model.PlatformAccountBinding, error) {
	f.setPrimaryCalled = true
	f.setPrimaryOwnerID = ownerUserID
	f.setPrimaryBinding = bindingID
	f.setPrimaryProfile = profileID
	if f.setPrimaryErr != nil {
		return nil, f.setPrimaryErr
	}
	if f.setPrimaryResult != nil {
		return f.setPrimaryResult, nil
	}
	return &model.PlatformAccountBinding{ID: bindingID, OwnerUserID: ownerUserID}, nil
}

type fakeGrantCleaner struct {
	called    bool
	bindingID uint64
	err       error
}

func (f *fakeGrantCleaner) DeleteGrants(bindingID uint64) error {
	f.called = true
	f.bindingID = bindingID
	return f.err
}

func (f *fakeCredentialGateway) PutCredential(context.Context, string, string, *model.PlatformAccountBinding, json.RawMessage) (map[string]any, error) {
	f.called = true
	if f.err != nil {
		return nil, f.err
	}
	return f.summary, nil
}

func (f *fakeCredentialGateway) RefreshCredential(context.Context, string, string, *model.PlatformAccountBinding) error {
	panic("unexpected call")
}

func (f *fakeCredentialGateway) DeleteCredential(_ context.Context, endpoint, ticket string, binding *model.PlatformAccountBinding) error {
	f.deleteCalled = true
	f.deleteCallCount++
	f.deleteEndpoint = endpoint
	f.deleteTicket = ticket
	if binding != nil {
		f.deleteBindingID = binding.ID
		f.deleteAccountKey = binding.ExternalAccountKey
	}
	return f.deleteErr
}

func (f *fakeRuntimeSummaryPlatformService) GetBindingRuntimeSummary(_ context.Context, actorType, actorID string, binding *model.PlatformAccountBinding, scopes []string) (map[string]any, error) {
	f.callCount++
	f.lastBinding = binding
	f.lastActorType = actorType
	f.lastActorID = actorID
	f.lastScopes = append([]string(nil), scopes...)
	if f.err != nil {
		return nil, f.err
	}
	return f.summary, nil
}

func TestRuntimeSummaryDelegatesToPlatformService(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:                 101,
		OwnerUserID:        7,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:10001", Valid: true},
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	fake := &fakeRuntimeSummaryPlatformService{summary: map[string]any{
		"status":   "active",
		"profiles": []map[string]any{{"player_id": "10001"}},
	}}
	svc := NewRuntimeSummaryService(fake, reader)

	summary, err := svc.GetRuntimeSummary(context.Background(), 7, 101)
	require.NoError(t, err)
	assert.Equal(t, "active", summary.Status)
	assert.Len(t, summary.Profiles, 1)
	assert.Equal(t, 1, fake.callCount)
	assert.Equal(t, uint64(7), reader.ownerID)
	assert.Equal(t, uint64(101), reader.id)
	assert.Equal(t, binding, fake.lastBinding)
	assert.Equal(t, "user", fake.lastActorType)
	assert.Equal(t, "binding-runtime-summary", fake.lastActorID)
	assert.Equal(t, []string{"mihomo.credential.read_meta"}, fake.lastScopes)
}

func TestRuntimeSummaryNormalizesGRPCProxyOutage(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:                 101,
		OwnerUserID:        7,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:10001", Valid: true},
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	fake := &fakeRuntimeSummaryPlatformService{err: grpcstatus.Error(codes.Unavailable, "downstream unavailable")}
	svc := NewRuntimeSummaryService(fake, reader)

	summary, err := svc.GetRuntimeSummary(context.Background(), 7, 101)
	require.ErrorIs(t, err, serviceplatform.ErrPlatformSummaryProxyUnavailable)
	assert.Nil(t, summary)
}

func TestRuntimeSummaryNormalizesDialFailure(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:                 101,
		OwnerUserID:        7,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:10001", Valid: true},
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	fake := &fakeRuntimeSummaryPlatformService{err: errors.New("dial tcp 127.0.0.1:9000: connectex: connection refused")}
	svc := NewRuntimeSummaryService(fake, reader)

	summary, err := svc.GetRuntimeSummary(context.Background(), 7, 101)
	require.ErrorIs(t, err, serviceplatform.ErrPlatformSummaryProxyUnavailable)
	assert.Nil(t, summary)
}

func TestRuntimeSummaryPreservesWrappedPlatformServiceUnavailable(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:                 101,
		OwnerUserID:        7,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:10001", Valid: true},
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	fake := &fakeRuntimeSummaryPlatformService{err: fmt.Errorf("wrapped: %w", serviceplatform.ErrPlatformServiceUnavailable)}
	svc := NewRuntimeSummaryService(fake, reader)

	summary, err := svc.GetRuntimeSummary(context.Background(), 7, 101)
	require.ErrorIs(t, err, serviceplatform.ErrPlatformServiceUnavailable)
	assert.Nil(t, summary)
	require.NotErrorIs(t, err, serviceplatform.ErrPlatformSummaryProxyUnavailable)
}

func TestRuntimeSummaryReturnsBindingNotReadyWhenExternalAccountKeyUnresolved(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:          101,
		OwnerUserID: 7,
		Platform:    "mihomo",
		Status:      model.PlatformAccountBindingStatusPendingBind,
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	fake := &fakeRuntimeSummaryPlatformService{}
	svc := NewRuntimeSummaryService(fake, reader)

	summary, err := svc.GetRuntimeSummary(context.Background(), 7, 101)
	require.ErrorIs(t, err, ErrBindingRuntimeSummaryNotReady)
	assert.Nil(t, summary)
	assert.Equal(t, 0, fake.callCount)
}

func TestRuntimeSummaryAsAdminReturnsBindingNotReadyWhenExternalAccountKeyUnresolved(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:       101,
		Platform: "mihomo",
		Status:   model.PlatformAccountBindingStatusPendingBind,
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	fake := &fakeRuntimeSummaryPlatformService{}
	svc := NewRuntimeSummaryService(fake, reader)

	summary, err := svc.GetRuntimeSummaryAsAdmin(context.Background(), 101)
	require.ErrorIs(t, err, ErrBindingRuntimeSummaryNotReady)
	assert.Nil(t, summary)
	assert.Equal(t, 0, fake.callCount)
}

func TestRefreshBindingForOwnerDelegatesToRefreshGateway(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:                 101,
		OwnerUserID:        7,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:10001", Valid: true},
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	platformSvc := &fakeOrchestrationPlatformService{
		platform: &model.PlatformService{Endpoint: "127.0.0.1:9000"},
		ticket:   "service-ticket",
	}
	gateway := &fakeRefreshGateway{err: errors.New("downstream unavailable")}
	svc := NewOrchestrationService(reader, platformSvc, gateway)

	updated, err := svc.RefreshBindingForOwner(context.Background(), 7, 101)
	require.Error(t, err)
	assert.Nil(t, updated)
	assert.True(t, gateway.called)
	assert.Equal(t, "127.0.0.1:9000", gateway.endpoint)
	assert.Equal(t, "service-ticket", gateway.ticket)
	assert.Equal(t, binding, gateway.binding)
	assert.Equal(t, []string{"mihomo.credential.refresh"}, platformSvc.lastScope)
	assert.False(t, reader.updated)
}

func TestDeleteBindingForOwnerDeletesProviderCredentialAndControlPlaneState(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:                 101,
		OwnerUserID:        7,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:10001", Valid: true},
		Status:             model.PlatformAccountBindingStatusActive,
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	platformSvc := &fakeOrchestrationPlatformService{
		platform: &model.PlatformService{Endpoint: "127.0.0.1:9000"},
		ticket:   "service-ticket",
	}
	gateway := &fakeCredentialGateway{}
	profileCleaner := &fakeProfileSyncer{}
	grantCleaner := &fakeGrantCleaner{}
	svc := NewOrchestrationService(reader, platformSvc, gateway, profileCleaner, grantCleaner)

	err := svc.DeleteBindingForOwner(context.Background(), 7, 101)
	require.NoError(t, err)
	assert.Equal(t, model.PlatformAccountBindingStatusDeleting, reader.updatedStatus)
	assert.True(t, gateway.deleteCalled)
	assert.Equal(t, "127.0.0.1:9000", gateway.deleteEndpoint)
	assert.Equal(t, "service-ticket", gateway.deleteTicket)
	assert.Equal(t, uint64(101), gateway.deleteBindingID)
	assert.False(t, profileCleaner.deleteCalled)
	assert.False(t, grantCleaner.called)
	assert.Equal(t, uint64(101), reader.deletedID)
	assert.Equal(t, []string{"mihomo.credential.delete"}, platformSvc.lastScope)
}

func TestDeleteBindingAsAdminMarksBindingDeleteFailedWhenProviderDeleteFails(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:                 101,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:10001", Valid: true},
		Status:             model.PlatformAccountBindingStatusActive,
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	platformSvc := &fakeOrchestrationPlatformService{
		platform: &model.PlatformService{Endpoint: "127.0.0.1:9000"},
		ticket:   "service-ticket",
	}
	gateway := &fakeCredentialGateway{deleteErr: errors.New("downstream unavailable")}
	profileCleaner := &fakeProfileSyncer{}
	grantCleaner := &fakeGrantCleaner{}
	svc := NewOrchestrationService(reader, platformSvc, gateway, profileCleaner, grantCleaner)

	err := svc.DeleteBindingAsAdmin(context.Background(), 101, 88)
	require.Error(t, err)
	assert.True(t, gateway.deleteCalled)
	assert.Equal(t, model.PlatformAccountBindingStatusDeleteFailed, reader.binding.Status)
	assert.Equal(t, "credential_delete_failed", reader.updatedReason)
	assert.Equal(t, "downstream unavailable", reader.updatedMessage)
	assert.False(t, profileCleaner.deleteCalled)
	assert.False(t, grantCleaner.called)
	assert.Zero(t, reader.deletedID)
	assert.Equal(t, []string{"mihomo.credential.delete"}, platformSvc.lastScope)
}

func TestDeleteBindingForOwnerSkipsProviderDeleteWhenBindingHasNoExternalAccountKey(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:          101,
		OwnerUserID: 7,
		Platform:    "mihomo",
		Status:      model.PlatformAccountBindingStatusPendingBind,
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	platformSvc := &fakeOrchestrationPlatformService{}
	gateway := &fakeCredentialGateway{}
	svc := NewOrchestrationService(reader, platformSvc, gateway)

	err := svc.DeleteBindingForOwner(context.Background(), 7, 101)
	require.NoError(t, err)
	assert.False(t, gateway.deleteCalled)
	assert.Zero(t, reader.updatedReason)
	assert.Equal(t, uint64(101), reader.deletedID)
	assert.Nil(t, platformSvc.lastScope)
}

func TestDeleteBindingForOwnerNormalizesMissingPlatformServiceAsUnavailable(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:                 101,
		OwnerUserID:        7,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:10001", Valid: true},
		Status:             model.PlatformAccountBindingStatusActive,
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	platformSvc := &fakeOrchestrationPlatformService{err: gorm.ErrRecordNotFound}
	gateway := &fakeCredentialGateway{}
	svc := NewOrchestrationService(reader, platformSvc, gateway)

	err := svc.DeleteBindingForOwner(context.Background(), 7, 101)
	require.ErrorIs(t, err, serviceplatform.ErrPlatformServiceUnavailable)
	assert.True(t, reader.updated)
	assert.Equal(t, model.PlatformAccountBindingStatusDeleteFailed, reader.binding.Status)
	assert.Equal(t, "credential_delete_failed", reader.updatedReason)
	assert.False(t, gateway.deleteCalled)
}

func TestDeleteBindingForOwnerMarksDeleteFailedWhenDraftCleanupDeleteFails(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:          101,
		OwnerUserID: 7,
		Platform:    "mihomo",
		Status:      model.PlatformAccountBindingStatusPendingBind,
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding, deleteErr: errors.New("cleanup delete failed")}
	platformSvc := &fakeOrchestrationPlatformService{}
	gateway := &fakeCredentialGateway{}
	svc := NewOrchestrationService(reader, platformSvc, gateway)

	err := svc.DeleteBindingForOwner(context.Background(), 7, 101)
	require.EqualError(t, err, "cleanup delete failed")
	assert.Equal(t, model.PlatformAccountBindingStatusDeleteFailed, reader.binding.Status)
	assert.Equal(t, "control_plane_cleanup_failed", reader.updatedReason)
	assert.Equal(t, "cleanup delete failed", reader.updatedMessage)
	assert.False(t, gateway.deleteCalled)
	assert.Nil(t, platformSvc.lastScope)
}

func TestDeleteBindingForOwnerMarksDeleteFailedWhenGatewayUnavailable(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:                 101,
		OwnerUserID:        7,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:10001", Valid: true},
		Status:             model.PlatformAccountBindingStatusActive,
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	platformSvc := &fakeOrchestrationPlatformService{}
	svc := NewOrchestrationService(reader, platformSvc, nil)

	err := svc.DeleteBindingForOwner(context.Background(), 7, 101)
	require.ErrorIs(t, err, ErrCredentialGatewayUnavailable)
	assert.Equal(t, model.PlatformAccountBindingStatusDeleteFailed, reader.binding.Status)
	assert.Equal(t, "credential_delete_failed", reader.updatedReason)
	assert.Equal(t, ErrCredentialGatewayUnavailable.Error(), reader.updatedMessage)
	assert.Nil(t, platformSvc.lastScope)
}

func TestDeleteBindingForOwnerRetriesControlPlaneCleanupWithoutRepeatingProviderDelete(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:                 101,
		OwnerUserID:        7,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:10001", Valid: true},
		Status:             model.PlatformAccountBindingStatusActive,
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding, deleteErr: errors.New("cleanup delete failed")}
	platformSvc := &fakeOrchestrationPlatformService{
		platform: &model.PlatformService{Endpoint: "127.0.0.1:9000"},
		ticket:   "service-ticket",
	}
	gateway := &fakeCredentialGateway{}
	svc := NewOrchestrationService(reader, platformSvc, gateway)

	err := svc.DeleteBindingForOwner(context.Background(), 7, 101)
	require.EqualError(t, err, "cleanup delete failed")
	assert.Equal(t, model.PlatformAccountBindingStatusDeleteFailed, reader.binding.Status)
	assert.Equal(t, "control_plane_cleanup_failed", reader.updatedReason)
	assert.Equal(t, 1, gateway.deleteCallCount)

	reader.deleteErr = nil
	err = svc.DeleteBindingForOwner(context.Background(), 7, 101)
	require.NoError(t, err)
	assert.Equal(t, uint64(101), reader.deletedID)
	assert.Equal(t, 1, gateway.deleteCallCount)
}

func TestPutCredentialForOwnerPersistsResolvedRuntimeState(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:          101,
		OwnerUserID: 7,
		Platform:    "mihomo",
		Status:      model.PlatformAccountBindingStatusPendingBind,
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	platformSvc := &fakeOrchestrationPlatformService{
		platform: &model.PlatformService{Endpoint: "127.0.0.1:9000"},
		ticket:   "service-ticket",
	}
	gateway := &fakeCredentialGateway{summary: map[string]any{
		"platform_account_id": "cn:resolved-account",
		"status":              "active",
		"last_validated_at":   "2026-04-19T12:34:56Z",
	}}
	svc := NewOrchestrationService(reader, platformSvc, gateway)

	summary, err := svc.PutCredentialForOwner(context.Background(), PutCredentialInput{
		OwnerUserID:       7,
		BindingID:         101,
		ActorType:         "user",
		ActorID:           "session:99",
		CredentialPayload: json.RawMessage(`{"cookie_bundle":"abc"}`),
	})
	require.NoError(t, err)
	require.NotNil(t, summary)
	assert.True(t, gateway.called)
	require.NotNil(t, reader.persistedSummary)
	assert.Equal(t, "cn:resolved-account", reader.persistedSummary.PlatformAccountID)
	assert.Equal(t, "active", reader.persistedSummary.Status)
	assert.Equal(t, []string{"mihomo.credential.bind"}, platformSvc.lastScope)
}

func TestPutCredentialForOwnerCompensatesOnResolvedBindingConflict(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:          101,
		OwnerUserID: 7,
		Platform:    "mihomo",
		Status:      model.PlatformAccountBindingStatusPendingBind,
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	platformSvc := &fakeOrchestrationPlatformService{
		platform: &model.PlatformService{Endpoint: "127.0.0.1:9000"},
		ticket:   "service-ticket",
	}
	reader.err = nil
	gateway := &fakeCredentialGateway{summary: map[string]any{
		"platform_account_id": "cn:resolved-account",
		"status":              "active",
	}}
	svc := NewOrchestrationService(failingPersistBindingReader{fakeRuntimeSummaryBindingReader: reader, err: ErrBindingAlreadyOwned}, platformSvc, gateway)

	summary, err := svc.PutCredentialForOwner(context.Background(), PutCredentialInput{
		OwnerUserID:       7,
		BindingID:         101,
		ActorType:         "user",
		ActorID:           "session:99",
		CredentialPayload: json.RawMessage(`{"cookie_bundle":"abc"}`),
	})
	require.ErrorIs(t, err, ErrBindingAlreadyOwned)
	assert.Nil(t, summary)
	assert.True(t, gateway.called)
	assert.True(t, gateway.deleteCalled)
	assert.Equal(t, uint64(101), gateway.deleteBindingID)
	assert.Equal(t, sql.NullString{String: "cn:resolved-account", Valid: true}, gateway.deleteAccountKey)
	assert.Equal(t, "127.0.0.1:9000", gateway.deleteEndpoint)
	assert.Equal(t, []string{"mihomo.credential.delete"}, platformSvc.lastScope)
	assert.Equal(t, model.PlatformAccountBindingStatusCredentialInvalid, reader.binding.Status)
	assert.Equal(t, "duplicate_owner", reader.updatedReason)
}

func TestPutCredentialForOwnerMarksDeleteFailedWhenCompensationFails(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:          101,
		OwnerUserID: 7,
		Platform:    "mihomo",
		Status:      model.PlatformAccountBindingStatusPendingBind,
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	platformSvc := &fakeOrchestrationPlatformService{
		platform: &model.PlatformService{Endpoint: "127.0.0.1:9000"},
		ticket:   "service-ticket",
	}
	gateway := &fakeCredentialGateway{
		summary: map[string]any{
			"platform_account_id": "cn:resolved-account",
			"status":              "active",
		},
		deleteErr: errors.New("cleanup unavailable"),
	}
	svc := NewOrchestrationService(failingPersistBindingReader{fakeRuntimeSummaryBindingReader: reader, err: ErrBindingAlreadyOwned}, platformSvc, gateway)

	summary, err := svc.PutCredentialForOwner(context.Background(), PutCredentialInput{
		OwnerUserID:       7,
		BindingID:         101,
		ActorType:         "user",
		ActorID:           "session:99",
		CredentialPayload: json.RawMessage(`{"cookie_bundle":"abc"}`),
	})
	require.ErrorIs(t, err, ErrBindingAlreadyOwned)
	assert.Nil(t, summary)
	assert.True(t, gateway.deleteCalled)
	assert.Equal(t, model.PlatformAccountBindingStatusDeleteFailed, reader.binding.Status)
	assert.Equal(t, "compensation_delete_failed", reader.updatedReason)
}

func TestPutCredentialForOwnerMarksDraftCredentialInvalidOnValidationFailure(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:          101,
		OwnerUserID: 7,
		Platform:    "mihomo",
		Status:      model.PlatformAccountBindingStatusPendingBind,
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	platformSvc := &fakeOrchestrationPlatformService{
		platform: &model.PlatformService{Endpoint: "127.0.0.1:9000"},
		ticket:   "service-ticket",
	}
	gateway := &fakeCredentialGateway{err: grpcstatus.Error(codes.InvalidArgument, "credential rejected")}
	svc := NewOrchestrationService(reader, platformSvc, gateway)

	summary, err := svc.PutCredentialForOwner(context.Background(), PutCredentialInput{
		OwnerUserID:       7,
		BindingID:         101,
		ActorType:         "user",
		ActorID:           "session:99",
		CredentialPayload: json.RawMessage(`{"cookie_bundle":"bad"}`),
	})
	require.ErrorIs(t, err, ErrCredentialValidationFailed)
	assert.Nil(t, summary)
	assert.Equal(t, model.PlatformAccountBindingStatusCredentialInvalid, reader.binding.Status)
	assert.Equal(t, "credential_validation_failed", reader.updatedReason)
}

func TestSetPrimaryProfileForOwnerRejectsForeignProfileBeforeExecutionPlaneCall(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:                 101,
		OwnerUserID:        7,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "binding_101_10001", Valid: true},
		Status:             model.PlatformAccountBindingStatusActive,
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	platformSvc := &fakeOrchestrationPlatformService{}
	profileSyncer := &fakeProfileSyncer{getProfileErr: ErrPrimaryProfileNotOwned}
	svc := NewOrchestrationService(reader, platformSvc, &fakeCredentialGateway{}, profileSyncer)

	updated, err := svc.SetPrimaryProfileForOwner(context.Background(), 7, 101, 404, "session:99")
	require.ErrorIs(t, err, ErrPrimaryProfileNotOwned)
	assert.Nil(t, updated)
	assert.False(t, platformSvc.confirmCalled)
	assert.False(t, profileSyncer.setPrimaryCalled)
	assert.Equal(t, uint64(101), profileSyncer.lastLookupBinding)
	assert.Equal(t, uint64(404), profileSyncer.lastLookupProfile)
}

func TestSetPrimaryProfileForOwnerRejectsExpiredExecutionPlaneTicketWithoutProjectionWrite(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:                 101,
		OwnerUserID:        7,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "binding_101_10001", Valid: true},
		Status:             model.PlatformAccountBindingStatusActive,
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	platformSvc := &fakeOrchestrationPlatformService{confirmPrimaryProfile: grpcstatus.Error(codes.Unauthenticated, "service ticket expired")}
	profileSyncer := &fakeProfileSyncer{profile: &model.PlatformAccountProfile{ID: 404, BindingID: 101, PlayerUID: "1008611"}}
	svc := NewOrchestrationService(reader, platformSvc, &fakeCredentialGateway{}, profileSyncer)

	updated, err := svc.SetPrimaryProfileForOwner(context.Background(), 7, 101, 404, "session:99")
	require.ErrorIs(t, err, ErrCredentialValidationFailed)
	assert.Nil(t, updated)
	assert.True(t, platformSvc.confirmCalled)
	assert.False(t, profileSyncer.setPrimaryCalled)
	assert.Contains(t, err.Error(), "service ticket expired")
}

func TestSetPrimaryProfileForOwnerRejectsExecutionPlanePrimaryProfileUpdateWithoutProjectionWrite(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:                 101,
		OwnerUserID:        7,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "binding_101_10001", Valid: true},
		Status:             model.PlatformAccountBindingStatusActive,
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	platformSvc := &fakeOrchestrationPlatformService{confirmPrimaryProfile: grpcstatus.Error(codes.InvalidArgument, "profile confirmation rejected")}
	profileSyncer := &fakeProfileSyncer{profile: &model.PlatformAccountProfile{ID: 404, BindingID: 101, PlayerUID: "1008611"}}
	svc := NewOrchestrationService(reader, platformSvc, &fakeCredentialGateway{}, profileSyncer)

	updated, err := svc.SetPrimaryProfileForOwner(context.Background(), 7, 101, 404, "session:99")
	require.ErrorIs(t, err, ErrCredentialValidationFailed)
	assert.Nil(t, updated)
	assert.True(t, platformSvc.confirmCalled)
	assert.False(t, profileSyncer.setPrimaryCalled)
	assert.Contains(t, err.Error(), "profile confirmation rejected")
}

func TestSetPrimaryProfileForOwnerConfirmsExecutionPlaneBeforeProjectionWrite(t *testing.T) {
	binding := &model.PlatformAccountBinding{
		ID:                 101,
		OwnerUserID:        7,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "binding_101_10001", Valid: true},
		Status:             model.PlatformAccountBindingStatusActive,
	}
	updatedBinding := &model.PlatformAccountBinding{
		ID:               101,
		OwnerUserID:      7,
		PrimaryProfileID: sql.NullInt64{Int64: 404, Valid: true},
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	platformSvc := &fakeOrchestrationPlatformService{}
	profileSyncer := &fakeProfileSyncer{
		profile:          &model.PlatformAccountProfile{ID: 404, BindingID: 101, PlayerUID: "1008611"},
		setPrimaryResult: updatedBinding,
	}
	svc := NewOrchestrationService(reader, platformSvc, &fakeCredentialGateway{}, profileSyncer)

	updated, err := svc.SetPrimaryProfileForOwner(context.Background(), 7, 101, 404, "session:99")
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.True(t, platformSvc.confirmCalled)
	assert.Equal(t, "user", platformSvc.confirmActorType)
	assert.Equal(t, "session:99", platformSvc.confirmActorID)
	assert.Equal(t, binding, platformSvc.confirmBinding)
	assert.Equal(t, "1008611", platformSvc.confirmPlayerID)
	assert.True(t, profileSyncer.setPrimaryCalled)
	assert.Equal(t, uint64(7), profileSyncer.setPrimaryOwnerID)
	assert.Equal(t, uint64(101), profileSyncer.setPrimaryBinding)
	if assert.NotNil(t, profileSyncer.setPrimaryProfile) {
		assert.Equal(t, uint64(404), *profileSyncer.setPrimaryProfile)
	}
	assert.Equal(t, updatedBinding, updated)
}

func TestCreateBindingForOwnerCreatesDraftBindsAndSyncsProfiles(t *testing.T) {
	reader := &fakeRuntimeSummaryBindingReader{}
	platformSvc := &fakeOrchestrationPlatformService{
		platform: &model.PlatformService{Endpoint: "127.0.0.1:9000", ServiceKey: "platform-mihomo-service"},
		ticket:   "service-ticket",
	}
	gateway := &fakeCredentialGateway{summary: map[string]any{
		"platform_account_id": "cn:resolved-account",
		"status":              "active",
		"profiles": []map[string]any{{
			"id":         uint64(42),
			"game_biz":   "hk4e_cn",
			"region":     "cn_gf01",
			"player_id":  "10001",
			"nickname":   "Traveler",
			"level":      int32(60),
			"is_default": true,
		}},
	}}
	profileSyncer := &fakeProfileSyncer{}
	svc := NewOrchestrationService(reader, platformSvc, gateway, profileSyncer)

	binding, err := svc.CreateBindingForOwner(context.Background(), CreateAndBindInput{
		OwnerUserID:       7,
		Platform:          "mihomo",
		DisplayName:       "Main Mihomo Account",
		ActorType:         "user",
		ActorID:           "session:99",
		CredentialPayload: json.RawMessage(`{"cookie_bundle":"abc"}`),
	})
	require.NoError(t, err)
	require.NotNil(t, binding)
	assert.Equal(t, uint64(7), binding.OwnerUserID)
	assert.Equal(t, "platform-mihomo-service", binding.PlatformServiceKey)
	assert.True(t, profileSyncer.called)
	assert.Equal(t, uint64(404), profileSyncer.input.BindingID)
	require.Len(t, profileSyncer.input.Profiles, 1)
	assert.Equal(t, "mihomo:42", profileSyncer.input.Profiles[0].PlatformProfileKey)
	assert.Equal(t, "10001", profileSyncer.input.Profiles[0].PlayerUID)
	assert.True(t, profileSyncer.input.Profiles[0].IsPrimary)
}

func TestCreateBindingForOwnerReturnsCommittedBindingWhenProfileSyncFails(t *testing.T) {
	reader := &fakeRuntimeSummaryBindingReader{}
	platformSvc := &fakeOrchestrationPlatformService{
		platform: &model.PlatformService{Endpoint: "127.0.0.1:9000", ServiceKey: "platform-mihomo-service"},
		ticket:   "service-ticket",
	}
	gateway := &fakeCredentialGateway{summary: map[string]any{
		"platform_account_id": "cn:resolved-account",
		"status":              "active",
		"profiles": []map[string]any{{
			"id":         uint64(42),
			"game_biz":   "hk4e_cn",
			"region":     "cn_gf01",
			"player_id":  "10001",
			"nickname":   "Traveler",
			"is_default": true,
		}},
	}}
	profileSyncer := &fakeProfileSyncer{err: errors.New("projection unavailable")}
	svc := NewOrchestrationService(reader, platformSvc, gateway, profileSyncer)

	binding, err := svc.CreateBindingForOwner(context.Background(), CreateAndBindInput{
		OwnerUserID:       7,
		Platform:          "mihomo",
		DisplayName:       "Main Mihomo Account",
		ActorType:         "user",
		ActorID:           "session:99",
		CredentialPayload: json.RawMessage(`{"cookie_bundle":"abc"}`),
	})
	require.NoError(t, err)
	require.NotNil(t, binding)
	assert.Equal(t, model.PlatformAccountBindingStatusActive, binding.Status)
	assert.Equal(t, "cn:resolved-account", binding.ExternalAccountKey.String)
	assert.True(t, profileSyncer.called)
}

func TestPutCredentialForOwnerReturnsExistingBindingForSameOwnerDuplicate(t *testing.T) {
	existing := &model.PlatformAccountBinding{
		ID:                 202,
		OwnerUserID:        7,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:resolved-account", Valid: true},
		Status:             model.PlatformAccountBindingStatusActive,
	}
	binding := &model.PlatformAccountBinding{
		ID:          101,
		OwnerUserID: 7,
		Platform:    "mihomo",
		Status:      model.PlatformAccountBindingStatusPendingBind,
	}
	reader := &fakeRuntimeSummaryBindingReader{binding: binding}
	platformSvc := &fakeOrchestrationPlatformService{
		platform: &model.PlatformService{Endpoint: "127.0.0.1:9000"},
		ticket:   "service-ticket",
	}
	gateway := &fakeCredentialGateway{summary: map[string]any{
		"platform_account_id": "cn:resolved-account",
		"status":              "active",
	}}
	svc := NewOrchestrationService(failingPersistBindingReader{fakeRuntimeSummaryBindingReader: reader, returnedBinding: existing}, platformSvc, gateway)

	summary, err := svc.PutCredentialForOwner(context.Background(), PutCredentialInput{
		OwnerUserID:       7,
		BindingID:         101,
		ActorType:         "user",
		ActorID:           "session:99",
		CredentialPayload: json.RawMessage(`{"cookie_bundle":"abc"}`),
	})
	require.NoError(t, err)
	require.NotNil(t, summary)
	assert.False(t, gateway.deleteCalled)
	assert.Empty(t, reader.updatedReason)
	assert.Equal(t, []string{"mihomo.credential.bind"}, platformSvc.lastScope)
	assert.Equal(t, uint64(101), reader.id)
	assert.Equal(t, "cn:resolved-account", summary.PlatformAccountID)
}

func TestCreateBindingForOwnerReturnsExistingBindingForSameOwnerDuplicate(t *testing.T) {
	existing := &model.PlatformAccountBinding{
		ID:                 202,
		OwnerUserID:        7,
		Platform:           "mihomo",
		PlatformServiceKey: "platform-mihomo-service",
		DisplayName:        "Existing Binding",
		ExternalAccountKey: sql.NullString{String: "cn:resolved-account", Valid: true},
		Status:             model.PlatformAccountBindingStatusActive,
	}
	reader := &fakeRuntimeSummaryBindingReader{ownerBinding: existing}
	platformSvc := &fakeOrchestrationPlatformService{
		platform: &model.PlatformService{Endpoint: "127.0.0.1:9000", ServiceKey: "platform-mihomo-service"},
		ticket:   "service-ticket",
	}
	gateway := &fakeCredentialGateway{summary: map[string]any{
		"platform_account_id": "cn:resolved-account",
		"status":              "active",
	}}
	svc := NewOrchestrationService(failingPersistBindingReader{fakeRuntimeSummaryBindingReader: reader, returnedBinding: existing}, platformSvc, gateway)

	binding, err := svc.CreateBindingForOwner(context.Background(), CreateAndBindInput{
		OwnerUserID:       7,
		Platform:          "mihomo",
		DisplayName:       "Retry Draft",
		ActorType:         "user",
		ActorID:           "session:99",
		CredentialPayload: json.RawMessage(`{"cookie_bundle":"abc"}`),
	})
	require.NoError(t, err)
	require.NotNil(t, binding)
	assert.Equal(t, uint64(202), binding.ID)
	assert.False(t, gateway.deleteCalled)
	assert.Equal(t, uint64(404), reader.deletedID)
}

type failingPersistBindingReader struct {
	*fakeRuntimeSummaryBindingReader
	err             error
	returnedBinding *model.PlatformAccountBinding
}

func (f failingPersistBindingReader) PersistRuntimeSummary(bindingID uint64, summary RuntimeSummary) (*model.PlatformAccountBinding, error) {
	f.fakeRuntimeSummaryBindingReader.id = bindingID
	f.fakeRuntimeSummaryBindingReader.persistedSummary = &summary
	return f.returnedBinding, f.err
}

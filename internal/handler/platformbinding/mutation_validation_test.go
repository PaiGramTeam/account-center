package platformbinding

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/middleware"
	"paigram/internal/model"
	"paigram/internal/response"
	serviceplatformbinding "paigram/internal/service/platformbinding"
)

type mutationBindingStub struct{}

func (mutationBindingStub) CreateBinding(serviceplatformbinding.CreateBindingInput) (*model.PlatformAccountBinding, error) {
	panic("unexpected call")
}
func (mutationBindingStub) GetBindingByID(uint64) (*model.PlatformAccountBinding, error) {
	return &model.PlatformAccountBinding{ID: 101, OwnerUserID: 7, Platform: "mihomo"}, nil
}
func (mutationBindingStub) GetBindingForOwner(ownerUserID, bindingID uint64) (*model.PlatformAccountBinding, error) {
	return &model.PlatformAccountBinding{ID: bindingID, OwnerUserID: ownerUserID, Platform: "mihomo"}, nil
}
func (mutationBindingStub) ListBindings(serviceplatformbinding.ListParams) ([]model.PlatformAccountBinding, int64, error) {
	panic("unexpected call")
}
func (mutationBindingStub) ListBindingsByOwner(uint64, serviceplatformbinding.ListParams) ([]model.PlatformAccountBinding, int64, error) {
	panic("unexpected call")
}
func (mutationBindingStub) UpdateBindingForOwner(uint64, uint64, serviceplatformbinding.UpdateBindingInput) (*model.PlatformAccountBinding, error) {
	panic("unexpected call")
}
func (mutationBindingStub) DeleteBinding(uint64) (*model.PlatformAccountBinding, error) {
	panic("unexpected call")
}
func (mutationBindingStub) DeleteBindingForOwner(uint64, uint64) (*model.PlatformAccountBinding, error) {
	panic("unexpected call")
}

type mutationProfileStub struct{}

func (s *mutationProfileStub) ListProfiles(uint64, serviceplatformbinding.ListParams) ([]model.PlatformAccountProfile, int64, error) {
	panic("unexpected call")
}
func (s *mutationProfileStub) ListProfilesForOwner(uint64, uint64, serviceplatformbinding.ListParams) ([]model.PlatformAccountProfile, int64, error) {
	panic("unexpected call")
}

type mutationGrantStub struct {
	upsertCalled         bool
	upsertForOwnerCalled bool
	revokeCalled         bool
	revokeForOwnerCalled bool
	upsertErr            error
	upsertForOwnerErr    error
}

func (s *mutationGrantStub) ListGrants(uint64, serviceplatformbinding.ListParams) ([]model.ConsumerGrant, int64, error) {
	panic("unexpected call")
}
func (s *mutationGrantStub) ListGrantsForOwner(uint64, uint64, serviceplatformbinding.ListParams) ([]model.ConsumerGrant, int64, error) {
	panic("unexpected call")
}
func (s *mutationGrantStub) UpsertGrant(serviceplatformbinding.UpsertGrantInput) (*model.ConsumerGrant, bool, error) {
	s.upsertCalled = true
	if s.upsertErr != nil {
		return nil, false, s.upsertErr
	}
	return &model.ConsumerGrant{}, true, nil
}
func (s *mutationGrantStub) UpsertGrantForOwner(uint64, serviceplatformbinding.UpsertGrantInput) (*model.ConsumerGrant, bool, error) {
	s.upsertForOwnerCalled = true
	if s.upsertForOwnerErr != nil {
		return nil, false, s.upsertForOwnerErr
	}
	return &model.ConsumerGrant{}, true, nil
}
func (s *mutationGrantStub) RevokeGrant(serviceplatformbinding.RevokeGrantInput) (*model.ConsumerGrant, error) {
	s.revokeCalled = true
	return &model.ConsumerGrant{Status: model.ConsumerGrantStatusRevoked, RevokedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}}, nil
}
func (s *mutationGrantStub) RevokeGrantForOwner(uint64, serviceplatformbinding.RevokeGrantInput) (*model.ConsumerGrant, error) {
	s.revokeForOwnerCalled = true
	return &model.ConsumerGrant{Status: model.ConsumerGrantStatusRevoked, RevokedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}}, nil
}

type mutationOrchestrationStub struct {
	setPrimaryCalled  bool
	setPrimaryOwnerID uint64
	setPrimaryBinding uint64
	setPrimaryProfile uint64
	setPrimaryActorID string
}

func (mutationOrchestrationStub) CreateBindingForOwner(context.Context, serviceplatformbinding.CreateAndBindInput) (*model.PlatformAccountBinding, error) {
	panic("unexpected call")
}

func (mutationOrchestrationStub) PutCredentialForOwner(context.Context, serviceplatformbinding.PutCredentialInput) (*serviceplatformbinding.RuntimeSummary, error) {
	panic("unexpected call")
}
func (mutationOrchestrationStub) PutCredentialAsAdmin(context.Context, serviceplatformbinding.PutCredentialInput) (*serviceplatformbinding.RuntimeSummary, error) {
	panic("unexpected call")
}
func (mutationOrchestrationStub) RefreshBindingForOwner(context.Context, uint64, uint64) (*model.PlatformAccountBinding, error) {
	panic("unexpected call")
}
func (s *mutationOrchestrationStub) SetPrimaryProfileForOwner(_ context.Context, ownerUserID, bindingID, profileID uint64, actorID string) (*model.PlatformAccountBinding, error) {
	s.setPrimaryCalled = true
	s.setPrimaryOwnerID = ownerUserID
	s.setPrimaryBinding = bindingID
	s.setPrimaryProfile = profileID
	s.setPrimaryActorID = actorID
	return &model.PlatformAccountBinding{ID: bindingID, OwnerUserID: ownerUserID}, nil
}
func (mutationOrchestrationStub) DeleteBindingForOwner(context.Context, uint64, uint64) error {
	panic("unexpected call")
}
func (mutationOrchestrationStub) RefreshBindingAsAdmin(context.Context, uint64) (*model.PlatformAccountBinding, error) {
	panic("unexpected call")
}
func (mutationOrchestrationStub) DeleteBindingAsAdmin(context.Context, uint64, uint64) error {
	panic("unexpected call")
}

type mutationRuntimeSummaryStub struct{}

func (mutationRuntimeSummaryStub) GetRuntimeSummary(context.Context, uint64, uint64) (*serviceplatformbinding.RuntimeSummary, error) {
	panic("unexpected call")
}
func (mutationRuntimeSummaryStub) GetRuntimeSummaryAsAdmin(context.Context, uint64) (*serviceplatformbinding.RuntimeSummary, error) {
	panic("unexpected call")
}

func TestMePatchPrimaryProfileRejectsMissingOrZeroProfileID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	orchestrationStub := &mutationOrchestrationStub{}
	handler := NewMeHandler(mutationBindingStub{}, &mutationProfileStub{}, &mutationGrantStub{}, orchestrationStub, mutationRuntimeSummaryStub{})

	tests := []struct {
		name string
		body string
	}{
		{name: "missing profile id", body: `{}`},
		{name: "zero profile id", body: `{"profile_id":0}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Params = []gin.Param{{Key: "bindingId", Value: "101"}}
			c.Request = httptest.NewRequest(http.MethodPatch, "/api/v1/me/platform-accounts/101/primary-profile", bytes.NewBufferString(tt.body))
			c.Request.Header.Set("Content-Type", "application/json")
			middleware.SetUserID(c, 7)

			handler.PatchPrimaryProfile(c)

			require.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), `"message":"profile_id is required"`)
			assert.False(t, orchestrationStub.setPrimaryCalled)
		})
	}
}

func TestMePutConsumerGrantRejectsMissingEnabledField(t *testing.T) {
	gin.SetMode(gin.TestMode)
	grantStub := &mutationGrantStub{}
	handler := NewMeHandler(mutationBindingStub{}, &mutationProfileStub{}, grantStub, &mutationOrchestrationStub{}, mutationRuntimeSummaryStub{})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = []gin.Param{{Key: "bindingId", Value: "101"}, {Key: "consumer", Value: "paigram-bot"}}
	c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/me/platform-accounts/101/consumer-grants/paigram-bot", bytes.NewBufferString(`{}`))
	c.Request.Header.Set("Content-Type", "application/json")
	middleware.SetUserID(c, 7)

	handler.PutConsumerGrant(c)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), `"message":"enabled is required"`)
	assert.False(t, grantStub.upsertForOwnerCalled)
	assert.False(t, grantStub.revokeForOwnerCalled)
}

func TestAdminPutConsumerGrantRejectsMissingEnabledField(t *testing.T) {
	gin.SetMode(gin.TestMode)
	grantStub := &mutationGrantStub{}
	handler := NewAdminHandler(mutationBindingStub{}, &mutationProfileStub{}, grantStub, &mutationOrchestrationStub{}, mutationRuntimeSummaryStub{})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = []gin.Param{{Key: "bindingId", Value: "101"}, {Key: "consumer", Value: "paigram-bot"}}
	c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/admin/platform-accounts/101/consumer-grants/paigram-bot", bytes.NewBufferString(`{}`))
	c.Request.Header.Set("Content-Type", "application/json")
	middleware.SetUserID(c, 9)

	handler.PutConsumerGrant(c)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), `"message":"enabled is required"`)
	assert.False(t, grantStub.upsertCalled)
	assert.False(t, grantStub.revokeCalled)
}

func TestMePatchPrimaryProfileAllowsNonZeroProfileID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	orchestrationStub := &mutationOrchestrationStub{}
	handler := NewMeHandler(mutationBindingStub{}, &mutationProfileStub{}, &mutationGrantStub{}, orchestrationStub, mutationRuntimeSummaryStub{})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = []gin.Param{{Key: "bindingId", Value: "101"}}
	c.Request = httptest.NewRequest(http.MethodPatch, "/api/v1/me/platform-accounts/101/primary-profile", bytes.NewBufferString(`{"profile_id":12}`))
	c.Request.Header.Set("Content-Type", "application/json")
	middleware.SetUserID(c, 7)

	handler.PatchPrimaryProfile(c)

	require.Equal(t, http.StatusOK, w.Code)
	require.True(t, orchestrationStub.setPrimaryCalled)
	assert.Equal(t, uint64(12), orchestrationStub.setPrimaryProfile)
	assert.Equal(t, uint64(7), orchestrationStub.setPrimaryOwnerID)
	assert.Equal(t, uint64(101), orchestrationStub.setPrimaryBinding)
	assert.Contains(t, w.Body.String(), fmt.Sprintf(`"id":%d`, 101))
}

func TestMePutConsumerGrantAllowsExplicitEnabledFalse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	grantStub := &mutationGrantStub{}
	handler := NewMeHandler(mutationBindingStub{}, &mutationProfileStub{}, grantStub, &mutationOrchestrationStub{}, mutationRuntimeSummaryStub{})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = []gin.Param{{Key: "bindingId", Value: strconv.FormatUint(101, 10)}, {Key: "consumer", Value: "paigram-bot"}}
	c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/me/platform-accounts/101/consumer-grants/paigram-bot", bytes.NewBufferString(`{"enabled":false}`))
	c.Request.Header.Set("Content-Type", "application/json")
	middleware.SetUserID(c, 7)

	handler.PutConsumerGrant(c)

	require.Equal(t, http.StatusOK, w.Code)
	assert.False(t, grantStub.upsertForOwnerCalled)
	assert.True(t, grantStub.revokeForOwnerCalled)
}

func TestMePutConsumerGrantReturnsCodedBadRequestForUnsupportedConsumer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	grantStub := &mutationGrantStub{upsertForOwnerErr: serviceplatformbinding.ErrConsumerNotSupported}
	handler := NewMeHandler(mutationBindingStub{}, &mutationProfileStub{}, grantStub, &mutationOrchestrationStub{}, mutationRuntimeSummaryStub{})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = []gin.Param{{Key: "bindingId", Value: "101"}, {Key: "consumer", Value: "unsupported-consumer"}}
	c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/me/platform-accounts/101/consumer-grants/unsupported-consumer", bytes.NewBufferString(`{"enabled":true}`))
	c.Request.Header.Set("Content-Type", "application/json")
	middleware.SetUserID(c, 7)

	handler.PutConsumerGrant(c)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.True(t, grantStub.upsertForOwnerCalled)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &payload))
	errorData, ok := payload["error"].(map[string]any)
	require.True(t, ok, "expected error map in response, got %T", payload["error"])
	assert.Equal(t, response.ErrCodeInvalidInput, errorData["code"])
	assert.Equal(t, "consumer is not supported", errorData["message"])
}

package platformbinding

import (
	"bytes"
	"context"
	"database/sql"
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

type mutationProfileStub struct {
	called    bool
	ownerID   uint64
	bindingID uint64
	profileID *uint64
}

func (s *mutationProfileStub) ListProfiles(uint64, serviceplatformbinding.ListParams) ([]model.PlatformAccountProfile, int64, error) {
	panic("unexpected call")
}
func (s *mutationProfileStub) ListProfilesForOwner(uint64, uint64, serviceplatformbinding.ListParams) ([]model.PlatformAccountProfile, int64, error) {
	panic("unexpected call")
}
func (s *mutationProfileStub) SetPrimaryProfileForOwner(ownerUserID, bindingID uint64, profileID *uint64) (*model.PlatformAccountBinding, error) {
	s.called = true
	s.ownerID = ownerUserID
	s.bindingID = bindingID
	s.profileID = profileID
	return &model.PlatformAccountBinding{ID: bindingID, OwnerUserID: ownerUserID}, nil
}

type mutationGrantStub struct {
	upsertCalled         bool
	upsertForOwnerCalled bool
	revokeCalled         bool
	revokeForOwnerCalled bool
}

func (s *mutationGrantStub) ListGrants(uint64, serviceplatformbinding.ListParams) ([]model.ConsumerGrant, int64, error) {
	panic("unexpected call")
}
func (s *mutationGrantStub) ListGrantsForOwner(uint64, uint64, serviceplatformbinding.ListParams) ([]model.ConsumerGrant, int64, error) {
	panic("unexpected call")
}
func (s *mutationGrantStub) UpsertGrant(serviceplatformbinding.UpsertGrantInput) (*model.ConsumerGrant, bool, error) {
	s.upsertCalled = true
	return &model.ConsumerGrant{}, true, nil
}
func (s *mutationGrantStub) UpsertGrantForOwner(uint64, serviceplatformbinding.UpsertGrantInput) (*model.ConsumerGrant, bool, error) {
	s.upsertForOwnerCalled = true
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

type mutationOrchestrationStub struct{}

func (mutationOrchestrationStub) PutCredentialForOwner(context.Context, serviceplatformbinding.PutCredentialInput) (*serviceplatformbinding.RuntimeSummary, error) {
	panic("unexpected call")
}
func (mutationOrchestrationStub) PutCredentialAsAdmin(context.Context, serviceplatformbinding.PutCredentialInput) (*serviceplatformbinding.RuntimeSummary, error) {
	panic("unexpected call")
}
func (mutationOrchestrationStub) RefreshBindingForOwner(context.Context, uint64, uint64) (*model.PlatformAccountBinding, error) {
	panic("unexpected call")
}
func (mutationOrchestrationStub) RefreshBindingAsAdmin(context.Context, uint64) (*model.PlatformAccountBinding, error) {
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
	profileStub := &mutationProfileStub{}
	handler := NewMeHandler(mutationBindingStub{}, profileStub, &mutationGrantStub{}, mutationOrchestrationStub{}, mutationRuntimeSummaryStub{})

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
			assert.False(t, profileStub.called)
		})
	}
}

func TestMePutConsumerGrantRejectsMissingEnabledField(t *testing.T) {
	gin.SetMode(gin.TestMode)
	grantStub := &mutationGrantStub{}
	handler := NewMeHandler(mutationBindingStub{}, &mutationProfileStub{}, grantStub, mutationOrchestrationStub{}, mutationRuntimeSummaryStub{})

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
	handler := NewAdminHandler(mutationBindingStub{}, &mutationProfileStub{}, grantStub, mutationOrchestrationStub{}, mutationRuntimeSummaryStub{})

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
	profileStub := &mutationProfileStub{}
	handler := NewMeHandler(mutationBindingStub{}, profileStub, &mutationGrantStub{}, mutationOrchestrationStub{}, mutationRuntimeSummaryStub{})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = []gin.Param{{Key: "bindingId", Value: "101"}}
	c.Request = httptest.NewRequest(http.MethodPatch, "/api/v1/me/platform-accounts/101/primary-profile", bytes.NewBufferString(`{"profile_id":12}`))
	c.Request.Header.Set("Content-Type", "application/json")
	middleware.SetUserID(c, 7)

	handler.PatchPrimaryProfile(c)

	require.Equal(t, http.StatusOK, w.Code)
	require.True(t, profileStub.called)
	require.NotNil(t, profileStub.profileID)
	assert.Equal(t, uint64(12), *profileStub.profileID)
	assert.Equal(t, uint64(7), profileStub.ownerID)
	assert.Equal(t, uint64(101), profileStub.bindingID)
	assert.Contains(t, w.Body.String(), fmt.Sprintf(`"id":%d`, 101))
}

func TestMePutConsumerGrantAllowsExplicitEnabledFalse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	grantStub := &mutationGrantStub{}
	handler := NewMeHandler(mutationBindingStub{}, &mutationProfileStub{}, grantStub, mutationOrchestrationStub{}, mutationRuntimeSummaryStub{})

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

package platformbinding

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"paigram/internal/model"
	serviceplatformbinding "paigram/internal/service/platformbinding"
)

type refreshBindingStub struct{}

func (refreshBindingStub) CreateBinding(serviceplatformbinding.CreateBindingInput) (*model.PlatformAccountBinding, error) {
	panic("unexpected call")
}
func (refreshBindingStub) GetBindingByID(uint64) (*model.PlatformAccountBinding, error) {
	panic("unexpected call")
}
func (refreshBindingStub) GetBindingForOwner(uint64, uint64) (*model.PlatformAccountBinding, error) {
	panic("unexpected call")
}
func (refreshBindingStub) ListBindings(serviceplatformbinding.ListParams) ([]model.PlatformAccountBinding, int64, error) {
	panic("unexpected call")
}
func (refreshBindingStub) ListBindingsByOwner(uint64, serviceplatformbinding.ListParams) ([]model.PlatformAccountBinding, int64, error) {
	panic("unexpected call")
}
func (refreshBindingStub) UpdateBindingForOwner(uint64, uint64, serviceplatformbinding.UpdateBindingInput) (*model.PlatformAccountBinding, error) {
	panic("unexpected call")
}
func (refreshBindingStub) DeleteBinding(uint64) (*model.PlatformAccountBinding, error) {
	panic("unexpected call")
}
func (refreshBindingStub) DeleteBindingForOwner(uint64, uint64) (*model.PlatformAccountBinding, error) {
	panic("unexpected call")
}
func (refreshBindingStub) RefreshBinding(uint64) (*model.PlatformAccountBinding, error) {
	panic("unexpected call")
}
func (refreshBindingStub) RefreshBindingForOwner(uint64, uint64) (*model.PlatformAccountBinding, error) {
	panic("unexpected call")
}

type refreshOrchestrationStub struct {
	ownerUserID uint64
	bindingID   uint64
	called      bool
}

func (s *refreshOrchestrationStub) CreateBindingForOwner(_ context.Context, _ serviceplatformbinding.CreateAndBindInput) (*model.PlatformAccountBinding, error) {
	panic("unexpected call")
}

func (s *refreshOrchestrationStub) PutCredentialForOwner(_ context.Context, _ serviceplatformbinding.PutCredentialInput) (*serviceplatformbinding.RuntimeSummary, error) {
	panic("unexpected call")
}
func (s *refreshOrchestrationStub) PutCredentialAsAdmin(_ context.Context, _ serviceplatformbinding.PutCredentialInput) (*serviceplatformbinding.RuntimeSummary, error) {
	panic("unexpected call")
}
func (s *refreshOrchestrationStub) RefreshBindingForOwner(_ context.Context, ownerUserID, bindingID uint64) (*model.PlatformAccountBinding, error) {
	s.called = true
	s.ownerUserID = ownerUserID
	s.bindingID = bindingID
	return &model.PlatformAccountBinding{ID: bindingID, OwnerUserID: ownerUserID, Platform: "mihomo", Status: model.PlatformAccountBindingStatusRefreshRequired}, nil
}
func (s *refreshOrchestrationStub) RefreshBindingAsAdmin(_ context.Context, _ uint64) (*model.PlatformAccountBinding, error) {
	panic("unexpected call")
}

func TestMeHandlerRefreshBindingUsesOrchestrationBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	orchestration := &refreshOrchestrationStub{}
	h := NewMeHandler(refreshBindingStub{}, nil, nil, orchestration, nil)
	g := gin.New()
	g.POST("/api/v1/me/platform-accounts/:bindingId/refresh", func(c *gin.Context) {
		c.Set("user_id", uint64(7))
		h.RefreshBinding(c)
	})

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/me/platform-accounts/101/refresh", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, orchestration.called)
	require.Equal(t, uint64(7), orchestration.ownerUserID)
	require.Equal(t, uint64(101), orchestration.bindingID)

	var body struct {
		Data map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, string(model.PlatformAccountBindingStatusRefreshRequired), body.Data["status"])
}

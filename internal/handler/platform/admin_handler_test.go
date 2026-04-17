package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	serviceplatform "paigram/internal/service/platform"
)

type fakePlatformAdminService struct {
	listView     []serviceplatform.PlatformServiceAdminView
	getView      *serviceplatform.PlatformServiceAdminView
	configView   *serviceplatform.UpdatePlatformServiceInput
	createView   *serviceplatform.PlatformServiceAdminView
	updateView   *serviceplatform.PlatformServiceAdminView
	checkView    *serviceplatform.PlatformServiceAdminView
	listErr      error
	getErr       error
	configErr    error
	createErr    error
	updateErr    error
	deleteErr    error
	checkErr     error
	lastGetID    uint64
	lastConfigID uint64
	lastCreate   serviceplatform.CreatePlatformServiceInput
	lastUpdateID uint64
	lastUpdate   serviceplatform.UpdatePlatformServiceInput
	lastDeleteID uint64
	lastCheckID  uint64
}

func (f *fakePlatformAdminService) ListPlatformServices(context.Context) ([]serviceplatform.PlatformServiceAdminView, error) {
	return f.listView, f.listErr
}

func (f *fakePlatformAdminService) GetPlatformService(_ context.Context, id uint64) (*serviceplatform.PlatformServiceAdminView, error) {
	f.lastGetID = id
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.getView, nil
}

func (f *fakePlatformAdminService) GetPlatformServiceConfig(_ context.Context, id uint64) (*serviceplatform.UpdatePlatformServiceInput, error) {
	f.lastConfigID = id
	if f.configErr != nil {
		return nil, f.configErr
	}
	return f.configView, nil
}

func (f *fakePlatformAdminService) CreatePlatformService(_ context.Context, input serviceplatform.CreatePlatformServiceInput) (*serviceplatform.PlatformServiceAdminView, error) {
	f.lastCreate = input
	if f.createErr != nil {
		return nil, f.createErr
	}
	return f.createView, nil
}

func (f *fakePlatformAdminService) UpdatePlatformService(_ context.Context, id uint64, input serviceplatform.UpdatePlatformServiceInput) (*serviceplatform.PlatformServiceAdminView, error) {
	f.lastUpdateID = id
	f.lastUpdate = input
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	return f.updateView, nil
}

func (f *fakePlatformAdminService) DeletePlatformService(_ context.Context, id uint64) error {
	f.lastDeleteID = id
	return f.deleteErr
}

func (f *fakePlatformAdminService) CheckPlatformService(_ context.Context, id uint64) (*serviceplatform.PlatformServiceAdminView, error) {
	f.lastCheckID = id
	if f.checkErr != nil {
		return nil, f.checkErr
	}
	return f.checkView, nil
}

func TestAdminHandlerListPlatformServices(t *testing.T) {
	gin.SetMode(gin.TestMode)

	checkedAt := time.Now().UTC()
	g := gin.New()
	h := NewAdminHandler(&fakePlatformAdminService{listView: []serviceplatform.PlatformServiceAdminView{{
		ID:           1,
		PlatformKey:  "mihomo",
		DisplayName:  "Mihomo",
		RuntimeState: serviceplatform.RuntimeStateHealthy,
		CheckedAt:    &checkedAt,
	}}})
	g.GET("/api/v1/platform-services", h.ListPlatformServices)

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/platform-services", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Data, 1)
	require.Equal(t, "mihomo", body.Data[0]["platform_key"])
	require.Equal(t, string(serviceplatform.RuntimeStateHealthy), body.Data[0]["runtime_state"])
}

func TestAdminHandlerCreatePlatformServiceInvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	h := NewAdminHandler(&fakePlatformAdminService{})
	g.POST("/api/v1/platform-services", h.CreatePlatformService)

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/platform-services", bytes.NewBufferString("{"))
	req.Header.Set("Content-Type", "application/json")
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Contains(t, body["message"], "invalid request payload")
}

func TestAdminHandlerDeletePlatformServiceReferenced(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	h := NewAdminHandler(&fakePlatformAdminService{deleteErr: serviceplatform.ErrPlatformServiceReferenced})
	g.DELETE("/api/v1/platform-services/:id", h.DeletePlatformService)

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/api/v1/platform-services/3", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusConflict, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Contains(t, body["message"], "platform service is still referenced")
}

func TestAdminHandlerGetPlatformServiceInvalidID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	h := NewAdminHandler(&fakePlatformAdminService{})
	g.GET("/api/v1/platform-services/:id", h.GetPlatformService)

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/platform-services/not-a-number", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "invalid platform service id", body["message"])
}

func TestAdminHandlerUpdatePlatformServiceMergesOmittedFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	existing := &serviceplatform.UpdatePlatformServiceInput{
		PlatformKey:      "mihomo",
		DisplayName:      "Mihomo",
		ServiceKey:       "platform-mihomo-service",
		ServiceAudience:  "mihomo.platform",
		DiscoveryType:    "static",
		Endpoint:         "127.0.0.1:50051",
		Enabled:          true,
		SupportedActions: []string{"bind_credential"},
		CredentialSchema: map[string]any{"type": "object"},
	}
	updatedView := &serviceplatform.PlatformServiceAdminView{DisplayName: "Mihomo CN"}

	fake := &fakePlatformAdminService{
		getErr:     errors.New("unexpected live probe path"),
		configView: existing,
		updateView: updatedView,
	}
	g := gin.New()
	h := NewAdminHandler(fake)
	g.PATCH("/api/v1/platform-services/:id", h.UpdatePlatformService)

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPatch, "/api/v1/platform-services/7", bytes.NewBufferString(`{"display_name":"Mihomo CN"}`))
	req.Header.Set("Content-Type", "application/json")
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Zero(t, fake.lastGetID)
	require.Equal(t, uint64(7), fake.lastConfigID)
	require.Equal(t, uint64(7), fake.lastUpdateID)
	require.Equal(t, "mihomo", fake.lastUpdate.PlatformKey)
	require.Equal(t, "Mihomo CN", fake.lastUpdate.DisplayName)
	require.Equal(t, "platform-mihomo-service", fake.lastUpdate.ServiceKey)
	require.Equal(t, "mihomo.platform", fake.lastUpdate.ServiceAudience)
	require.Equal(t, "static", fake.lastUpdate.DiscoveryType)
	require.Equal(t, "127.0.0.1:50051", fake.lastUpdate.Endpoint)
	require.True(t, fake.lastUpdate.Enabled)
	require.Equal(t, []string{"bind_credential"}, fake.lastUpdate.SupportedActions)
	require.Equal(t, map[string]any{"type": "object"}, fake.lastUpdate.CredentialSchema)
}

func TestAdminHandlerUpdatePlatformServiceMergesZeroValues(t *testing.T) {
	gin.SetMode(gin.TestMode)

	existing := &serviceplatform.UpdatePlatformServiceInput{
		PlatformKey:      "mihomo",
		DisplayName:      "Mihomo",
		ServiceKey:       "platform-mihomo-service",
		ServiceAudience:  "mihomo.platform",
		DiscoveryType:    "static",
		Endpoint:         "127.0.0.1:50051",
		Enabled:          true,
		SupportedActions: []string{"bind_credential"},
		CredentialSchema: map[string]any{"type": "object", "required": []any{"token"}},
	}

	fake := &fakePlatformAdminService{
		configView: existing,
		updateView: &serviceplatform.PlatformServiceAdminView{},
	}
	g := gin.New()
	h := NewAdminHandler(fake)
	g.PATCH("/api/v1/platform-services/:id", h.UpdatePlatformService)

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPatch, "/api/v1/platform-services/7", bytes.NewBufferString(`{"enabled":false,"supported_actions":[],"credential_schema":{}}`))
	req.Header.Set("Content-Type", "application/json")
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.False(t, fake.lastUpdate.Enabled)
	require.Equal(t, []string{}, fake.lastUpdate.SupportedActions)
	require.Equal(t, map[string]any{}, fake.lastUpdate.CredentialSchema)
}

func TestAdminHandlerCheckPlatformServiceNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	h := NewAdminHandler(&fakePlatformAdminService{checkErr: gorm.ErrRecordNotFound})
	g.POST("/api/v1/platform-services/:id/check", h.CheckPlatformService)

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/platform-services/9/check", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "platform service not found", body["message"])
}

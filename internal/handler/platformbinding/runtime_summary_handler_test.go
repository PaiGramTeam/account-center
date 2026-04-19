package platformbinding

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	serviceplatform "paigram/internal/service/platform"
	serviceplatformbinding "paigram/internal/service/platformbinding"
)

type runtimeSummaryStub struct {
	err         error
	ownerUserID uint64
	bindingID   uint64
	called      bool
}

func (s *runtimeSummaryStub) GetRuntimeSummary(_ context.Context, ownerUserID, bindingID uint64) (*serviceplatformbinding.RuntimeSummary, error) {
	s.called = true
	s.ownerUserID = ownerUserID
	s.bindingID = bindingID
	return nil, s.err
}

func (s *runtimeSummaryStub) GetRuntimeSummaryAsAdmin(_ context.Context, bindingID uint64) (*serviceplatformbinding.RuntimeSummary, error) {
	s.called = true
	s.bindingID = bindingID
	return nil, s.err
}

func TestMeHandlerGetRuntimeSummaryReturnsServiceUnavailableForProxyOutage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	runtimeSvc := &runtimeSummaryStub{err: serviceplatform.ErrPlatformSummaryProxyUnavailable}
	h := NewMeHandler(refreshBindingStub{}, nil, nil, &refreshOrchestrationStub{}, runtimeSvc)
	g := gin.New()
	g.GET("/api/v1/me/platform-accounts/:bindingId/runtime-summary", func(c *gin.Context) {
		c.Set("user_id", uint64(7))
		h.GetRuntimeSummary(c)
	})

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/platform-accounts/101/runtime-summary", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.True(t, runtimeSvc.called)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "platform service unavailable", body["message"])
}

func TestAdminHandlerGetRuntimeSummaryReturnsServiceUnavailableForProxyOutage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	runtimeSvc := &runtimeSummaryStub{err: serviceplatform.ErrPlatformSummaryProxyUnavailable}
	h := NewAdminHandler(refreshBindingStub{}, nil, nil, &refreshOrchestrationStub{}, runtimeSvc)
	g := gin.New()
	g.GET("/api/v1/admin/platform-accounts/:bindingId/runtime-summary", h.GetRuntimeSummary)

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/admin/platform-accounts/101/runtime-summary", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.True(t, runtimeSvc.called)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "platform service unavailable", body["message"])
}

func TestMeHandlerGetRuntimeSummaryReturnsConflictForBindingNotReady(t *testing.T) {
	gin.SetMode(gin.TestMode)
	runtimeSvc := &runtimeSummaryStub{err: serviceplatformbinding.ErrBindingRuntimeSummaryNotReady}
	h := NewMeHandler(refreshBindingStub{}, nil, nil, &refreshOrchestrationStub{}, runtimeSvc)
	g := gin.New()
	g.GET("/api/v1/me/platform-accounts/:bindingId/runtime-summary", func(c *gin.Context) {
		c.Set("user_id", uint64(7))
		h.GetRuntimeSummary(c)
	})

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/platform-accounts/101/runtime-summary", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusConflict, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "platform binding runtime summary is not ready", body["message"])
}

func TestAdminHandlerGetRuntimeSummaryReturnsConflictForBindingNotReady(t *testing.T) {
	gin.SetMode(gin.TestMode)
	runtimeSvc := &runtimeSummaryStub{err: serviceplatformbinding.ErrBindingRuntimeSummaryNotReady}
	h := NewAdminHandler(refreshBindingStub{}, nil, nil, &refreshOrchestrationStub{}, runtimeSvc)
	g := gin.New()
	g.GET("/api/v1/admin/platform-accounts/:bindingId/runtime-summary", h.GetRuntimeSummary)

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/admin/platform-accounts/101/runtime-summary", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusConflict, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "platform binding runtime summary is not ready", body["message"])
}

func TestMeHandlerGetRuntimeSummaryReturnsServiceUnavailableForRealGRPCOutage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	runtimeSvc := &runtimeSummaryStub{err: grpcstatus.Error(codes.Unavailable, "downstream unavailable")}
	h := NewMeHandler(refreshBindingStub{}, nil, nil, &refreshOrchestrationStub{}, runtimeSvc)
	g := gin.New()
	g.GET("/api/v1/me/platform-accounts/:bindingId/runtime-summary", func(c *gin.Context) {
		c.Set("user_id", uint64(7))
		h.GetRuntimeSummary(c)
	})

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/platform-accounts/101/runtime-summary", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "platform service unavailable", body["message"])
}

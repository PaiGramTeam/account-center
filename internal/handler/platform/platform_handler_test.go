package platform

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	serviceplatform "paigram/internal/service/platform"
)

type fakePlatformService struct {
	platforms []serviceplatform.PlatformListView
	platform  *serviceplatform.PlatformSchemaView
	summary   map[string]any
	listErr   error
	getErr    error
}

func (f fakePlatformService) ListEnabledPlatformViews() ([]serviceplatform.PlatformListView, error) {
	return f.platforms, f.listErr
}

func (f fakePlatformService) GetPlatformSchemaView(platformKey string) (*serviceplatform.PlatformSchemaView, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.platform != nil && f.platform.Platform == platformKey {
		return f.platform, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func (f fakePlatformService) GetPlatformAccountSummary(_ context.Context, actorType, actorID string, ownerUserID, platformAccountRefID uint64, scopes []string) (map[string]any, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.summary, nil
}

func TestListPlatforms(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	h := NewHandler(fakePlatformService{platforms: []serviceplatform.PlatformListView{{
		Platform:         "hoyoverse",
		DisplayName:      "Hoyoverse",
		SupportedActions: []string{"bind_credential", "delete_credential"},
	}}})
	g.GET("/api/v1/me/platforms", h.ListPlatforms)

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/platforms", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Data, 1)
	require.Equal(t, "hoyoverse", body.Data[0]["platform"])
	require.Equal(t, "Hoyoverse", body.Data[0]["display_name"])
	require.Equal(t, []any{"bind_credential", "delete_credential"}, body.Data[0]["supported_actions"])
}

func TestGetPlatformSchema(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	h := NewHandler(fakePlatformService{platform: &serviceplatform.PlatformSchemaView{
		Platform:         "hoyoverse",
		DisplayName:      "Hoyoverse",
		SupportedActions: []string{"bind_credential"},
		CredentialSchema: map[string]any{"type": "object", "required": []any{"cookie_bundle"}},
	}})
	g.GET("/api/v1/me/platforms/:platform/schema", h.GetPlatformSchema)

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/platforms/hoyoverse/schema", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Data map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "hoyoverse", body.Data["platform"])
	require.Equal(t, "Hoyoverse", body.Data["display_name"])
	require.Equal(t, []any{"bind_credential"}, body.Data["supported_actions"])
	require.Equal(t, map[string]any{"type": "object", "required": []any{"cookie_bundle"}}, body.Data["credential_schema"])
}

func TestGetPlatformSchemaNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	h := NewHandler(fakePlatformService{getErr: gorm.ErrRecordNotFound})
	g.GET("/api/v1/me/platforms/:platform/schema", h.GetPlatformSchema)

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/platforms/missing/schema", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "platform not found", body["message"])
}

func TestListPlatformsServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	h := NewHandler(fakePlatformService{listErr: errors.New("boom")})
	g.GET("/api/v1/me/platforms", h.ListPlatforms)

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/platforms", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestGetPlatformAccountSummary(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	h := NewHandler(fakePlatformService{summary: map[string]any{"status": "active"}})
	g.GET("/api/v1/me/platform-accounts/:refId/summary", func(c *gin.Context) {
		c.Set("user_id", uint64(7))
		c.Set("session_id", uint64(99))
		h.GetPlatformAccountSummary(c)
	})

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/platform-accounts/11/summary", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Data map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "active", body.Data["status"])
}

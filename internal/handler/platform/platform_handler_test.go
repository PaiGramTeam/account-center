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
	platforms       []serviceplatform.PlatformListView
	platform        *serviceplatform.PlatformSchemaView
	summary         map[string]any
	listErr         error
	schemaErr       error
	summaryErr      error
	summaryCalls    int
	lastActorType   string
	lastActorID     string
	lastOwnerUserID uint64
	lastRefID       uint64
	lastScopes      []string
}

func (f *fakePlatformService) ListEnabledPlatformViews() ([]serviceplatform.PlatformListView, error) {
	return f.platforms, f.listErr
}

func (f *fakePlatformService) GetPlatformSchemaView(platformKey string) (*serviceplatform.PlatformSchemaView, error) {
	if f.schemaErr != nil {
		return nil, f.schemaErr
	}
	if f.platform != nil && f.platform.Platform == platformKey {
		return f.platform, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func (f *fakePlatformService) GetPlatformAccountSummary(_ context.Context, actorType, actorID string, ownerUserID, platformAccountRefID uint64, scopes []string) (map[string]any, error) {
	f.summaryCalls++
	f.lastActorType = actorType
	f.lastActorID = actorID
	f.lastOwnerUserID = ownerUserID
	f.lastRefID = platformAccountRefID
	f.lastScopes = append([]string(nil), scopes...)
	if f.summaryErr != nil {
		return nil, f.summaryErr
	}
	return f.summary, nil
}

func TestListPlatforms(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	h := NewHandler(&fakePlatformService{platforms: []serviceplatform.PlatformListView{{
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
	h := NewHandler(&fakePlatformService{platform: &serviceplatform.PlatformSchemaView{
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
	h := NewHandler(&fakePlatformService{schemaErr: gorm.ErrRecordNotFound})
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
	h := NewHandler(&fakePlatformService{listErr: errors.New("boom")})
	g.GET("/api/v1/me/platforms", h.ListPlatforms)

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/platforms", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestGetPlatformAccountSummary(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	fake := &fakePlatformService{summary: map[string]any{"status": "active"}}
	h := NewHandler(fake)
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
	require.Equal(t, 1, fake.summaryCalls)
	require.Equal(t, "web_user", fake.lastActorType)
	require.Equal(t, "session:99", fake.lastActorID)
	require.Equal(t, uint64(7), fake.lastOwnerUserID)
	require.Equal(t, uint64(11), fake.lastRefID)
	require.Equal(t, []string{"mihomo.credential.read_meta"}, fake.lastScopes)
}

func TestGetPlatformAccountSummaryUnauthenticated(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	h := NewHandler(&fakePlatformService{})
	g.GET("/api/v1/me/platform-accounts/:refId/summary", h.GetPlatformAccountSummary)

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/platform-accounts/11/summary", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "user not authenticated", body["message"])
}

func TestGetPlatformAccountSummaryMissingSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	h := NewHandler(&fakePlatformService{})
	g.GET("/api/v1/me/platform-accounts/:refId/summary", func(c *gin.Context) {
		c.Set("user_id", uint64(7))
		h.GetPlatformAccountSummary(c)
	})

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/platform-accounts/11/summary", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "session not found", body["message"])
}

func TestGetPlatformAccountSummaryNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	h := NewHandler(&fakePlatformService{summaryErr: gorm.ErrRecordNotFound})
	g.GET("/api/v1/me/platform-accounts/:refId/summary", func(c *gin.Context) {
		c.Set("user_id", uint64(7))
		c.Set("session_id", uint64(99))
		h.GetPlatformAccountSummary(c)
	})

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/platform-accounts/11/summary", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "platform account not found", body["message"])
}

func TestGetPlatformAccountSummaryPlatformServiceUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	h := NewHandler(&fakePlatformService{summaryErr: serviceplatform.ErrPlatformSummaryProxyUnavailable})
	g.GET("/api/v1/me/platform-accounts/:refId/summary", func(c *gin.Context) {
		c.Set("user_id", uint64(7))
		c.Set("session_id", uint64(99))
		h.GetPlatformAccountSummary(c)
	})

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/platform-accounts/11/summary", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "platform service unavailable", body["message"])
}

func TestGetPlatformAccountSummaryInvalidRefID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	h := NewHandler(&fakePlatformService{})
	g.GET("/api/v1/me/platform-accounts/:refId/summary", func(c *gin.Context) {
		c.Set("user_id", uint64(7))
		c.Set("session_id", uint64(99))
		h.GetPlatformAccountSummary(c)
	})

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/platform-accounts/not-a-number/summary", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "invalid platform account ref id", body["message"])
}

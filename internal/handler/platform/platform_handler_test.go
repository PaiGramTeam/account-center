package platform

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/model"
	serviceplatform "paigram/internal/service/platform"
	"paigram/internal/testutil"
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

type realSummaryProxy struct {
	summary map[string]any
}

func (p *realSummaryProxy) GetCredentialSummary(_ context.Context, _, _, _ string) (map[string]any, error) {
	return p.summary, nil
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
	g.GET("/api/v1/me/platform-accounts/:bindingId/summary", func(c *gin.Context) {
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
	require.Equal(t, "user", fake.lastActorType)
	require.Equal(t, "session:99", fake.lastActorID)
	require.Equal(t, uint64(7), fake.lastOwnerUserID)
	require.Equal(t, uint64(11), fake.lastRefID)
	require.Equal(t, []string{"mihomo.credential.read_meta"}, fake.lastScopes)
}

func TestGetPlatformAccountSummaryWithRealService(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db := testutil.OpenMySQLTestDB(t, "platform_handler_real", &model.User{}, &model.PlatformAccountBinding{}, &model.PlatformAccountProfile{})
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		PlatformServiceKey: "platform-mihomo-service",
		ExternalAccountKey: sql.NullString{String: "cn:handler-summary", Valid: true},
		DisplayName:        "Traveler",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)
	profile := model.PlatformAccountProfile{BindingID: binding.ID, PlatformProfileKey: "mihomo:10001", GameBiz: "hk4e_cn", Region: "cn_gf01", PlayerUID: "10001", Nickname: "Traveler", IsPrimary: true}
	require.NoError(t, db.Create(&profile).Error)
	require.NoError(t, db.Model(&binding).Update("primary_profile_id", profile.ID).Error)

	group := serviceplatform.NewServiceGroup(db)
	service := &group.PlatformService
	require.NoError(t, service.ConfigureAuth(config.AuthConfig{
		ServiceTicketTTLSeconds: 300,
		ServiceTicketIssuer:     "account-center",
		ServiceTicketSigningKey: "0123456789abcdef0123456789abcdef",
	}))

	g := gin.New()
	h := NewHandler(service)
	g.GET("/api/v1/me/platform-accounts/:bindingId/summary", func(c *gin.Context) {
		c.Set("user_id", owner.ID)
		c.Set("session_id", uint64(99))
		h.GetPlatformAccountSummary(c)
	})

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/platform-accounts/"+fmt.Sprintf("%d", binding.ID)+"/summary", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Data map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "Traveler", body.Data["display_name"])
	require.Equal(t, float64(profile.ID), body.Data["primary_profile_id"])
}

func TestGetPlatformAccountSummaryUnauthenticated(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	h := NewHandler(&fakePlatformService{})
	g.GET("/api/v1/me/platform-accounts/:bindingId/summary", h.GetPlatformAccountSummary)

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
	g.GET("/api/v1/me/platform-accounts/:bindingId/summary", func(c *gin.Context) {
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
	g.GET("/api/v1/me/platform-accounts/:bindingId/summary", func(c *gin.Context) {
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
	errorBody, ok := body["error"].(map[string]any)
	require.True(t, ok, "expected error body, got %T", body["error"])
	require.Equal(t, "PLATFORM_BINDING_NOT_FOUND", errorBody["code"])
	require.Equal(t, "platform account not found", errorBody["message"])
}

func TestGetPlatformAccountSummaryPlatformServiceUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	h := NewHandler(&fakePlatformService{summaryErr: serviceplatform.ErrPlatformSummaryProxyUnavailable})
	g.GET("/api/v1/me/platform-accounts/:bindingId/summary", func(c *gin.Context) {
		c.Set("user_id", uint64(7))
		c.Set("session_id", uint64(99))
		h.GetPlatformAccountSummary(c)
	})

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/me/platform-accounts/11/summary", nil)
	g.ServeHTTP(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	errorBody, ok := body["error"].(map[string]any)
	require.True(t, ok, "expected error body, got %T", body["error"])
	require.Equal(t, "PLATFORM_SERVICE_UNAVAILABLE", errorBody["code"])
	require.Equal(t, "platform service unavailable", errorBody["message"])
}

func TestGetPlatformAccountSummaryInvalidRefID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	g := gin.New()
	h := NewHandler(&fakePlatformService{})
	g.GET("/api/v1/me/platform-accounts/:bindingId/summary", func(c *gin.Context) {
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
	require.Equal(t, "invalid binding id", body["message"])
}

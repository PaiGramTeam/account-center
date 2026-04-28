package platformbinding

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"paigram/internal/middleware"
	"paigram/internal/model"
	serviceplatformbinding "paigram/internal/service/platformbinding"
	"paigram/internal/testutil"
)

type noopOrchestrationService struct{}

func (noopOrchestrationService) CreateBindingForOwner(_ context.Context, _ serviceplatformbinding.CreateAndBindInput) (*model.PlatformAccountBinding, error) {
	return nil, nil
}

func (noopOrchestrationService) PutCredentialForOwner(_ context.Context, _ serviceplatformbinding.PutCredentialInput) (*serviceplatformbinding.RuntimeSummary, error) {
	return nil, nil
}

func (noopOrchestrationService) PutCredentialAsAdmin(_ context.Context, _ serviceplatformbinding.PutCredentialInput) (*serviceplatformbinding.RuntimeSummary, error) {
	return nil, nil
}

func (noopOrchestrationService) RefreshBindingForOwner(_ context.Context, _ uint64, _ uint64) (*model.PlatformAccountBinding, error) {
	return nil, nil
}

func (noopOrchestrationService) SetPrimaryProfileForOwner(_ context.Context, _ uint64, _ uint64, _ uint64, _ string) (*model.PlatformAccountBinding, error) {
	return nil, nil
}

func (noopOrchestrationService) DeleteBindingForOwner(_ context.Context, _ uint64, _ uint64) error {
	return nil
}

func (noopOrchestrationService) RefreshBindingAsAdmin(_ context.Context, _ uint64, _ uint64) (*model.PlatformAccountBinding, error) {
	return nil, nil
}

func (noopOrchestrationService) DeleteBindingAsAdmin(_ context.Context, _ uint64, _ uint64) error {
	return nil
}

type noopRuntimeSummaryService struct{}

func (noopRuntimeSummaryService) GetRuntimeSummary(_ context.Context, _ uint64, _ uint64) (*serviceplatformbinding.RuntimeSummary, error) {
	return nil, nil
}

func (noopRuntimeSummaryService) GetRuntimeSummaryAsAdmin(_ context.Context, _ uint64) (*serviceplatformbinding.RuntimeSummary, error) {
	return nil, nil
}

func TestAdminListBindingsReturnsCanonicalPaginationPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupPlatformBindingHandlerTestDB(t)
	bindingService := serviceplatformbinding.NewBindingService(db)
	profileService := serviceplatformbinding.NewProfileProjectionService(db)
	grantService := serviceplatformbinding.NewGrantService(db)
	handler := NewAdminHandler(bindingService, profileService, grantService, noopOrchestrationService{}, noopRuntimeSummaryService{})

	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	for i := 0; i < 3; i++ {
		_, err := bindingService.CreateBinding(serviceplatformbinding.CreateBindingInput{
			OwnerUserID:        owner.ID,
			Platform:           "mihomo",
			ExternalAccountKey: handlerNS(fmt.Sprintf("cn:handler:%d", i)),
			PlatformServiceKey: "mihomo",
			DisplayName:        fmt.Sprintf("Handler %d", i),
		})
		require.NoError(t, err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/admin/platform-accounts?page=2&page_size=1", nil)
	handler.ListBindings(c)

	require.Equal(t, http.StatusOK, w.Code)
	assertCanonicalPaginationPayload(t, w.Body.Bytes(), 1, 3, 2, 1, 3)
}

func TestMeListBindingsReturnsCanonicalPaginationPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupPlatformBindingHandlerTestDB(t)
	bindingService := serviceplatformbinding.NewBindingService(db)
	profileService := serviceplatformbinding.NewProfileProjectionService(db)
	grantService := serviceplatformbinding.NewGrantService(db)
	handler := NewMeHandler(bindingService, profileService, grantService, noopOrchestrationService{}, noopRuntimeSummaryService{})

	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	for i := 0; i < 3; i++ {
		_, err := bindingService.CreateBinding(serviceplatformbinding.CreateBindingInput{
			OwnerUserID:        owner.ID,
			Platform:           "mihomo",
			ExternalAccountKey: handlerNS(fmt.Sprintf("cn:me-handler:%d", i)),
			PlatformServiceKey: "mihomo",
			DisplayName:        fmt.Sprintf("Me Handler %d", i),
		})
		require.NoError(t, err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/me/platform-accounts?page=2&page_size=1", nil)
	middleware.SetUserID(c, owner.ID)
	handler.ListBindings(c)

	require.Equal(t, http.StatusOK, w.Code)
	assertCanonicalPaginationPayload(t, w.Body.Bytes(), 1, 3, 2, 1, 3)
}

func TestAdminListProfilesReturnsCanonicalPaginationPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupPlatformBindingHandlerTestDB(t)
	bindingService := serviceplatformbinding.NewBindingService(db)
	profileService := serviceplatformbinding.NewProfileProjectionService(db)
	grantService := serviceplatformbinding.NewGrantService(db)
	handler := NewAdminHandler(bindingService, profileService, grantService, noopOrchestrationService{}, noopRuntimeSummaryService{})

	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding, err := bindingService.CreateBinding(serviceplatformbinding.CreateBindingInput{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: handlerNS("cn:handler:profiles"),
		PlatformServiceKey: "mihomo",
		DisplayName:        "Profile Handler",
	})
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		require.NoError(t, db.Create(&model.PlatformAccountProfile{
			BindingID:          binding.ID,
			PlatformProfileKey: fmt.Sprintf("gs:%d", i),
			GameBiz:            "hk4e_cn",
			Region:             "cn_gf01",
			PlayerUID:          fmt.Sprintf("1000%d", i),
			Nickname:           fmt.Sprintf("Traveler %d", i),
			IsPrimary:          i == 0,
		}).Error)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = []gin.Param{{Key: "bindingId", Value: strconv.FormatUint(binding.ID, 10)}}
	c.Request = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/admin/platform-accounts/%d/profiles?page=2&page_size=1", binding.ID), nil)
	handler.ListProfiles(c)

	require.Equal(t, http.StatusOK, w.Code)
	assertCanonicalPaginationPayload(t, w.Body.Bytes(), 1, 3, 2, 1, 3)
}

func TestAdminListConsumerGrantsReturnsCanonicalPaginationPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupPlatformBindingHandlerTestDB(t)
	bindingService := serviceplatformbinding.NewBindingService(db)
	profileService := serviceplatformbinding.NewProfileProjectionService(db)
	grantService := serviceplatformbinding.NewGrantService(db)
	handler := NewAdminHandler(bindingService, profileService, grantService, noopOrchestrationService{}, noopRuntimeSummaryService{})

	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding, err := bindingService.CreateBinding(serviceplatformbinding.CreateBindingInput{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: handlerNS("cn:admin-handler:grant"),
		PlatformServiceKey: "mihomo",
		DisplayName:        "Admin Grant Handler",
	})
	require.NoError(t, err)
	for _, consumer := range []string{"paigram-bot", "pamgram", "mihomo.sync"} {
		require.NoError(t, db.Create(&model.ConsumerGrant{BindingID: binding.ID, Consumer: consumer, Status: model.ConsumerGrantStatusActive}).Error)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = []gin.Param{{Key: "bindingId", Value: strconv.FormatUint(binding.ID, 10)}}
	c.Request = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/admin/platform-accounts/%d/consumer-grants?page=2&page_size=1", binding.ID), nil)
	handler.ListConsumerGrants(c)

	require.Equal(t, http.StatusOK, w.Code)
	assertCanonicalPaginationPayload(t, w.Body.Bytes(), 1, 3, 2, 1, 3)
}

func TestMeListProfilesReturnsCanonicalPaginationPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupPlatformBindingHandlerTestDB(t)
	bindingService := serviceplatformbinding.NewBindingService(db)
	profileService := serviceplatformbinding.NewProfileProjectionService(db)
	grantService := serviceplatformbinding.NewGrantService(db)
	handler := NewMeHandler(bindingService, profileService, grantService, noopOrchestrationService{}, noopRuntimeSummaryService{})

	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding, err := bindingService.CreateBinding(serviceplatformbinding.CreateBindingInput{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: handlerNS("cn:me-handler:profiles"),
		PlatformServiceKey: "mihomo",
		DisplayName:        "Me Profile Handler",
	})
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		require.NoError(t, db.Create(&model.PlatformAccountProfile{
			BindingID:          binding.ID,
			PlatformProfileKey: fmt.Sprintf("me-gs:%d", i),
			GameBiz:            "hk4e_cn",
			Region:             "cn_gf01",
			PlayerUID:          fmt.Sprintf("2000%d", i),
			Nickname:           fmt.Sprintf("Owner Traveler %d", i),
			IsPrimary:          i == 0,
		}).Error)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = []gin.Param{{Key: "bindingId", Value: strconv.FormatUint(binding.ID, 10)}}
	c.Request = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/me/platform-accounts/%d/profiles?page=2&page_size=1", binding.ID), nil)
	middleware.SetUserID(c, owner.ID)
	handler.ListProfiles(c)

	require.Equal(t, http.StatusOK, w.Code)
	assertCanonicalPaginationPayload(t, w.Body.Bytes(), 1, 3, 2, 1, 3)
}

func TestMeListConsumerGrantsReturnsCanonicalPaginationPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupPlatformBindingHandlerTestDB(t)
	bindingService := serviceplatformbinding.NewBindingService(db)
	profileService := serviceplatformbinding.NewProfileProjectionService(db)
	grantService := serviceplatformbinding.NewGrantService(db)
	handler := NewMeHandler(bindingService, profileService, grantService, noopOrchestrationService{}, noopRuntimeSummaryService{})

	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding, err := bindingService.CreateBinding(serviceplatformbinding.CreateBindingInput{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: handlerNS("cn:handler:grant"),
		PlatformServiceKey: "mihomo",
		DisplayName:        "Grant Handler",
	})
	require.NoError(t, err)
	for _, consumer := range []string{"paigram-bot", "pamgram"} {
		require.NoError(t, db.Create(&model.ConsumerGrant{BindingID: binding.ID, Consumer: consumer, Status: model.ConsumerGrantStatusActive}).Error)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = []gin.Param{{Key: "bindingId", Value: strconv.FormatUint(binding.ID, 10)}}
	c.Request = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/me/platform-accounts/%d/consumer-grants?page=1&page_size=1", binding.ID), nil)
	middleware.SetUserID(c, owner.ID)
	handler.ListConsumerGrants(c)

	require.Equal(t, http.StatusOK, w.Code)
	assertCanonicalPaginationPayload(t, w.Body.Bytes(), 1, 2, 1, 1, 2)
}

func TestAdminListBindingsNormalizesInvalidPaginationParams(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupPlatformBindingHandlerTestDB(t)
	bindingService := serviceplatformbinding.NewBindingService(db)
	profileService := serviceplatformbinding.NewProfileProjectionService(db)
	grantService := serviceplatformbinding.NewGrantService(db)
	handler := NewAdminHandler(bindingService, profileService, grantService, noopOrchestrationService{}, noopRuntimeSummaryService{})

	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	for i := 0; i < 3; i++ {
		_, err := bindingService.CreateBinding(serviceplatformbinding.CreateBindingInput{
			OwnerUserID:        owner.ID,
			Platform:           "mihomo",
			ExternalAccountKey: handlerNS(fmt.Sprintf("cn:admin-normalize:%d", i)),
			PlatformServiceKey: "mihomo",
			DisplayName:        fmt.Sprintf("Admin Normalize %d", i),
		})
		require.NoError(t, err)
	}

	tests := []struct {
		name             string
		query            string
		expectedPage     int
		expectedPageSize int
		expectedItems    int
		expectedPages    int
	}{
		{name: "page zero", query: "?page=0&page_size=1", expectedPage: 1, expectedPageSize: 1, expectedItems: 1, expectedPages: 3},
		{name: "page size zero", query: "?page=2&page_size=0", expectedPage: 2, expectedPageSize: 20, expectedItems: 0, expectedPages: 1},
		{name: "page size above max", query: "?page=1&page_size=101", expectedPage: 1, expectedPageSize: 20, expectedItems: 3, expectedPages: 1},
		{name: "non numeric values", query: "?page=abc&page_size=nope", expectedPage: 1, expectedPageSize: 20, expectedItems: 3, expectedPages: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/admin/platform-accounts"+tt.query, nil)

			handler.ListBindings(c)

			require.Equal(t, http.StatusOK, w.Code)
			assertCanonicalPaginationPayload(t, w.Body.Bytes(), tt.expectedItems, 3, tt.expectedPage, tt.expectedPageSize, tt.expectedPages)
		})
	}
}

func TestMeListProfilesNormalizesInvalidPaginationParams(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupPlatformBindingHandlerTestDB(t)
	bindingService := serviceplatformbinding.NewBindingService(db)
	profileService := serviceplatformbinding.NewProfileProjectionService(db)
	grantService := serviceplatformbinding.NewGrantService(db)
	handler := NewMeHandler(bindingService, profileService, grantService, noopOrchestrationService{}, noopRuntimeSummaryService{})

	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding, err := bindingService.CreateBinding(serviceplatformbinding.CreateBindingInput{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: handlerNS("cn:me-normalize:profiles"),
		PlatformServiceKey: "mihomo",
		DisplayName:        "Me Normalize Profiles",
	})
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		require.NoError(t, db.Create(&model.PlatformAccountProfile{
			BindingID:          binding.ID,
			PlatformProfileKey: fmt.Sprintf("normalize-gs:%d", i),
			GameBiz:            "hk4e_cn",
			Region:             "cn_gf01",
			PlayerUID:          fmt.Sprintf("3000%d", i),
			Nickname:           fmt.Sprintf("Normalize Traveler %d", i),
			IsPrimary:          i == 0,
		}).Error)
	}

	tests := []struct {
		name             string
		query            string
		expectedPage     int
		expectedPageSize int
		expectedItems    int
		expectedPages    int
	}{
		{name: "page zero", query: "?page=0&page_size=1", expectedPage: 1, expectedPageSize: 1, expectedItems: 1, expectedPages: 3},
		{name: "page size zero", query: "?page=2&page_size=0", expectedPage: 2, expectedPageSize: 20, expectedItems: 0, expectedPages: 1},
		{name: "page size above max", query: "?page=1&page_size=101", expectedPage: 1, expectedPageSize: 20, expectedItems: 3, expectedPages: 1},
		{name: "non numeric values", query: "?page=abc&page_size=nope", expectedPage: 1, expectedPageSize: 20, expectedItems: 3, expectedPages: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Params = []gin.Param{{Key: "bindingId", Value: strconv.FormatUint(binding.ID, 10)}}
			c.Request = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/me/platform-accounts/%d/profiles%s", binding.ID, tt.query), nil)
			middleware.SetUserID(c, owner.ID)

			handler.ListProfiles(c)

			require.Equal(t, http.StatusOK, w.Code)
			assertCanonicalPaginationPayload(t, w.Body.Bytes(), tt.expectedItems, 3, tt.expectedPage, tt.expectedPageSize, tt.expectedPages)
		})
	}
}

func setupPlatformBindingHandlerTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db := testutil.OpenMySQLTestDB(t, "platformbinding_handler")
	for _, fileName := range []string{
		"000001_create_users_table.up.sql",
		"000011_create_roles_table.up.sql",
		"000013_create_user_roles_table.up.sql",
		"000034_add_primary_role_id_to_users.up.sql",
		"000035_create_platform_account_bindings_table.up.sql",
		"000036_create_platform_account_profiles_table.up.sql",
		"000037_create_consumer_grants_table.up.sql",
		"000038_alter_platform_account_bindings_for_phase_two.up.sql",
		"000044_add_scopes_json_to_consumer_grants.up.sql",
		"000045_add_consumer_grant_ticket_versions.up.sql",
	} {
		require.NoError(t, db.Exec(readPlatformBindingHandlerMigration(t, fileName)).Error)
	}

	return db
}

func assertCanonicalPaginationPayload(t *testing.T, body []byte, expectedItems, expectedTotal, expectedPage, expectedPageSize, expectedTotalPages int) {
	t.Helper()

	var payload map[string]any
	require.NoError(t, json.Unmarshal(body, &payload))
	data, ok := payload["data"].(map[string]any)
	require.True(t, ok)
	items, ok := data["items"].([]any)
	require.True(t, ok)
	require.Len(t, items, expectedItems)
	pagination, ok := data["pagination"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(expectedTotal), pagination["total"])
	assert.Equal(t, float64(expectedPage), pagination["page"])
	assert.Equal(t, float64(expectedPageSize), pagination["page_size"])
	assert.Equal(t, float64(expectedTotalPages), pagination["total_pages"])
}

func handlerNS(value string) sql.NullString {
	return sql.NullString{String: value, Valid: true}
}

func readPlatformBindingHandlerMigration(t *testing.T, fileName string) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	require.True(t, ok)

	path := filepath.Join(filepath.Dir(currentFile), "..", "..", "..", "initialize", "migrate", "sql", fileName)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(content)
}

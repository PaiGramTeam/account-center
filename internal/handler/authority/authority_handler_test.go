package authority

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gorm.io/gorm"

	"paigram/internal/model"
	"paigram/internal/response"
	serviceauthority "paigram/internal/service/authority"
	"paigram/internal/testutil"
)

func setupAuthorityHandlerTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	return testutil.OpenMySQLTestDB(t, "authority_handler",
		&model.Permission{},
		&model.Role{},
		&model.RolePermission{},
		&model.User{},
		&model.UserRole{},
	)
}

func TestReplaceAuthorityUsersRequiresAuthenticatedActor(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewAuthorityHandler(nil)
	body, err := json.Marshal(ReplaceAuthorityUsersRequest{UserIDs: []uint64{1}})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = []gin.Param{{Key: "id", Value: "1"}}
	c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/authorities/1/users", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.ReplaceAuthorityUsers(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "authentication required")
}

func TestSwaggerSourcesDoNotAdvertiseLegacyAuthorityOrCasbinRoutes(t *testing.T) {
	authoritySource, err := os.ReadFile("authority_handler.go")
	require.NoError(t, err)
	assert.NotContains(t, string(authoritySource), "/api/v1/authorities/")
	assert.NotContains(t, string(authoritySource), "/api/v1/authorities ")

	casbinSource, err := os.ReadFile(filepath.Join("..", "casbin", "swagger_routes.go"))
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(casbinSource), "/api/v1/casbin/"), "legacy casbin swagger routes should be removed")
}

func TestListAuthoritiesReturnsCanonicalPaginatedEnvelope(t *testing.T) {
	db := setupAuthorityHandlerTestDB(t)
	require.NoError(t, db.Create(&model.Role{Name: "role-a", DisplayName: "Role A"}).Error)
	require.NoError(t, db.Create(&model.Role{Name: "role-b", DisplayName: "Role B"}).Error)

	serviceGroup := serviceauthority.NewServiceGroup(db, nil)
	handler := NewAuthorityHandler(&serviceGroup.AuthorityService)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/admin/roles?page=0&page_size=0", nil)

	handler.ListAuthorities(c)

	require.Equal(t, http.StatusOK, w.Code)

	var resp response.Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	data, ok := resp.Data.(map[string]any)
	require.True(t, ok)
	assert.Contains(t, data, "items")
	assert.Contains(t, data, "pagination")
	assert.NotContains(t, data, "total")
	assert.NotContains(t, data, "page")
	assert.NotContains(t, data, "page_size")

	items, ok := data["items"].([]any)
	require.True(t, ok)
	assert.Len(t, items, 2)

	pagination, ok := data["pagination"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(2), pagination["total"])
	assert.Equal(t, float64(1), pagination["page"])
	assert.Equal(t, float64(10), pagination["page_size"])
	assert.Equal(t, float64(1), pagination["total_pages"])
}

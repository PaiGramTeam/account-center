package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"paigram/internal/model"
	"paigram/internal/response"
	"paigram/internal/service"
)

func TestRequire2FA(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("returns forbidden when 2fa is not enabled", func(t *testing.T) {
		db := setupTwoFATestDB(t)
		restore := setMiddlewareTestServiceGroup(t, db)
		defer restore()

		recorder := performTwoFARequest(t, Require2FA(), uint64(1))

		require.Equal(t, http.StatusForbidden, recorder.Code)
		assert.Equal(t, "2FA_REQUIRED", decodeMiddlewareErrorCode(t, recorder))
	})

	t.Run("returns internal server error when 2fa lookup fails", func(t *testing.T) {
		db := setupTwoFATestDB(t)
		require.NoError(t, db.Migrator().DropTable(&model.UserTwoFactor{}))
		restore := setMiddlewareTestServiceGroup(t, db)
		defer restore()

		recorder := performTwoFARequest(t, Require2FA(), uint64(1))

		require.Equal(t, http.StatusInternalServerError, recorder.Code)
		assert.Equal(t, "2FA_CHECK_FAILED", decodeMiddlewareErrorCode(t, recorder))
	})
}

func TestOptional2FA(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("sets has_2fa false when 2fa is not enabled", func(t *testing.T) {
		db := setupTwoFATestDB(t)
		restore := setMiddlewareTestServiceGroup(t, db)
		defer restore()

		recorder := performTwoFARequest(t, Optional2FA(), uint64(1))

		require.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, true, decodeMiddlewareData(t, recorder)["has_2fa_checked"])
		assert.Equal(t, false, decodeMiddlewareData(t, recorder)["has_2fa"])
	})

	t.Run("returns internal server error when 2fa lookup fails", func(t *testing.T) {
		db := setupTwoFATestDB(t)
		require.NoError(t, db.Migrator().DropTable(&model.UserTwoFactor{}))
		restore := setMiddlewareTestServiceGroup(t, db)
		defer restore()

		recorder := performTwoFARequest(t, Optional2FA(), uint64(1))

		require.Equal(t, http.StatusInternalServerError, recorder.Code)
		assert.Equal(t, "2FA_CHECK_FAILED", decodeMiddlewareErrorCode(t, recorder))
	})
}

func setupTwoFATestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.UserTwoFactor{}))
	return db
}

func setMiddlewareTestServiceGroup(t *testing.T, db *gorm.DB) func() {
	t.Helper()

	previous := service.ServiceGroupApp
	service.ServiceGroupApp = service.NewServiceGroup(db)
	return func() {
		service.ServiceGroupApp = previous
	}
}

func performTwoFARequest(t *testing.T, middleware gin.HandlerFunc, userID uint64) *httptest.ResponseRecorder {
	t.Helper()

	router := gin.New()
	router.Use(func(c *gin.Context) {
		SetUserID(c, userID)
		c.Next()
	})
	router.GET("/", middleware, func(c *gin.Context) {
		response.Success(c, gin.H{
			"has_2fa_checked": true,
			"has_2fa":         Has2FA(c),
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func decodeMiddlewareErrorCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()

	var payload map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
	errorPayload, ok := payload["error"].(map[string]any)
	require.True(t, ok)
	code, _ := errorPayload["code"].(string)
	return code
}

func decodeMiddlewareData(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var payload map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
	data, ok := payload["data"].(map[string]any)
	require.True(t, ok)
	return data
}

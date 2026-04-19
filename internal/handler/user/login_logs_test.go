package user

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"paigram/internal/model"
	"paigram/internal/response"
)

func setupLoginLogsHandlerTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.LoginLog{}))
	return db
}

func TestHandler_GetLoginLogsReturnsCanonicalPaginatedEnvelope(t *testing.T) {
	db := setupLoginLogsHandlerTestDB(t)
	handler := NewHandlerWithDB(nil, db)

	createdAt := time.Now().UTC().Truncate(time.Millisecond)
	const userID uint64 = 1001
	logs := []model.LoginLog{
		{
			UserID:        userID,
			LoginType:     model.LoginTypeEmail,
			IP:            "192.0.2.10",
			UserAgent:     "Mozilla/5.0",
			Device:        "Chrome / Windows",
			Location:      "Beijing, China",
			Status:        "success",
			FailureReason: "",
			CreatedAt:     createdAt,
		},
		{
			UserID:        userID,
			LoginType:     model.LoginTypeOAuth,
			IP:            "192.0.2.11",
			UserAgent:     "curl/8.0",
			Device:        "CLI / Linux",
			Location:      "Shanghai, China",
			Status:        "failed",
			FailureReason: "invalid_password",
			CreatedAt:     createdAt.Add(time.Minute),
		},
	}
	for i := range logs {
		require.NoError(t, db.Create(&logs[i]).Error)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/users/:id/login-logs", handler.GetLoginLogs)

	req := httptest.NewRequest(http.MethodGet, "/users/"+strconv.FormatUint(userID, 10)+"/login-logs?page=1&page_size=1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp response.Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	data, ok := resp.Data.(map[string]any)
	require.True(t, ok)
	assert.NotContains(t, data, "data")

	items, ok := data["items"].([]any)
	require.True(t, ok)
	require.Len(t, items, 1)

	item, ok := items[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(logs[1].ID), item["id"])
	assert.Equal(t, "failed", item["status"])
	assert.Equal(t, "invalid_password", item["failure_reason"])

	pagination, ok := data["pagination"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(2), pagination["total"])
	assert.Equal(t, float64(1), pagination["page"])
	assert.Equal(t, float64(1), pagination["page_size"])
	assert.Equal(t, float64(2), pagination["total_pages"])
}

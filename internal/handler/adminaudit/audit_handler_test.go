package adminaudit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/response"
	serviceaudit "paigram/internal/service/audit"
)

type stubAuditReader struct {
	items []serviceaudit.AuditEventView
	total int64
	err   error
}

func (s stubAuditReader) ListAuditLogs(context.Context, serviceaudit.ListAuditLogsFilter) ([]serviceaudit.AuditEventView, int64, error) {
	return s.items, s.total, s.err
}

func (s stubAuditReader) GetAuditLog(context.Context, uint64) (*serviceaudit.AuditEventView, error) {
	return nil, nil
}

func TestListAuditLogsReturnsCanonicalPaginatedEnvelope(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewAuditHandler(stubAuditReader{
		items: []serviceaudit.AuditEventView{{
			ID:        1,
			Category:  "role",
			ActorType: "admin",
			Action:    "create",
			Result:    "success",
			CreatedAt: "2026-04-19T12:00:00.000Z",
		}},
		total: 3,
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-logs?page=2&page_size=1", nil)

	handler.ListAuditLogs(c)

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
	assert.Len(t, items, 1)

	pagination, ok := data["pagination"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(3), pagination["total"])
	assert.Equal(t, float64(2), pagination["page"])
	assert.Equal(t, float64(1), pagination["page_size"])
	assert.Equal(t, float64(3), pagination["total_pages"])
	assert.NotContains(t, data, "meta")
}

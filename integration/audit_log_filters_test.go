//go:build integration

package integration

import (
	"database/sql"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/model"
)

func TestAdminAuditRoutesRequireAdminEvenWithAuditPermission(t *testing.T) {
	stack := newIntegrationStack(t)
	userID, accessToken, _, _, _ := registerAndLogin(t, stack, "audit-viewer-"+time.Now().Format("20060102150405.000000")+"@example.com", "ViewerPass123!")
	grantPermissionsToUser(t, stack, userID, model.PermAuditRead)

	resp := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/admin/audit-logs", nil, authHeaders(accessToken))
	require.Equal(t, http.StatusForbidden, resp.Code, resp.Body.String())
	assert.Equal(t, "ADMIN_REQUIRED", decodeErrorCode(t, resp))
	assert.Contains(t, resp.Body.String(), "admin role required")
	_ = userID
}

func TestAuditLogFiltersByCategory(t *testing.T) {
	stack := newIntegrationStack(t)
	userID, accessToken, _, _, _ := registerAndLogin(t, stack, "audit-admin-"+time.Now().Format("20060102150405.000000")+"@example.com", "AdminPass123!")
	grantAdminRoleToUser(t, stack, userID)

	loginEvent := seedAuditEvent(t, stack, model.AuditEvent{
		Category:     "login",
		ActorType:    "user",
		ActorUserID:  sql.NullInt64{Int64: int64(userID), Valid: true},
		Action:       "login_succeeded",
		TargetType:   "user",
		TargetID:     "100",
		Result:       "success",
		RequestID:    "req-login",
		IP:           "192.0.2.10",
		UserAgent:    "AuditTest/1.0",
		MetadataJSON: `{"provider":"email"}`,
		CreatedAt:    time.Now().UTC().Add(-2 * time.Minute),
	})
	binding := model.PlatformAccountBinding{
		OwnerUserID:        userID,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "binding-200", Valid: true},
		PlatformServiceKey: "platform-mihomo-service",
		DisplayName:        "Bound Mihomo Account",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, stack.DB.Create(&binding).Error)
	seedAuditEvent(t, stack, model.AuditEvent{
		Category:     "platform_binding",
		ActorType:    "user",
		ActorUserID:  sql.NullInt64{Int64: int64(userID), Valid: true},
		Action:       "refresh_failed",
		TargetType:   "binding",
		TargetID:     "binding-200",
		BindingID:    sql.NullInt64{Int64: int64(binding.ID), Valid: true},
		Result:       "failure",
		ReasonCode:   "upstream_unavailable",
		RequestID:    "req-binding",
		IP:           "192.0.2.20",
		UserAgent:    "AuditTest/1.0",
		MetadataJSON: `{"platform":"mihomo","owner":{"user_id":` + strconv.FormatUint(userID, 10) + `}}`,
		CreatedAt:    time.Now().UTC().Add(-1 * time.Minute),
	})

	resp := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/admin/audit-logs?category=login", nil, authHeaders(accessToken))
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

	data := decodeResponseData(t, resp)
	items, ok := data["items"].([]any)
	require.True(t, ok, "expected items array, got %T", data["items"])
	require.Len(t, items, 1)
	first, ok := items[0].(map[string]any)
	require.True(t, ok, "expected first audit item object, got %T", items[0])
	require.Equal(t, "login", first["category"])
	require.Equal(t, "success", first["result"])

	failureResp := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/admin/audit-logs?result=failure", nil, authHeaders(accessToken))
	require.Equal(t, http.StatusOK, failureResp.Code, failureResp.Body.String())
	failureData := decodeResponseData(t, failureResp)
	failureItems, ok := failureData["items"].([]any)
	require.True(t, ok, "expected items array, got %T", failureData["items"])
	require.Len(t, failureItems, 1)
	failureItem, ok := failureItems[0].(map[string]any)
	require.True(t, ok, "expected audit item object, got %T", failureItems[0])
	require.Equal(t, "platform_binding", failureItem["category"])
	require.Equal(t, "upstream_unavailable", failureItem["reason_code"])
	require.Equal(t, float64(binding.ID), failureItem["binding_id"])
	metadata, ok := failureItem["metadata"].(map[string]any)
	require.True(t, ok, "expected metadata object, got %T", failureItem["metadata"])
	require.Equal(t, "mihomo", metadata["platform"])

	detailResp := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/admin/audit-logs/"+formatUint(loginEvent.ID), nil, authHeaders(accessToken))
	require.Equal(t, http.StatusOK, detailResp.Code, detailResp.Body.String())
	detailData := decodeResponseData(t, detailResp)
	require.Equal(t, float64(loginEvent.ID), detailData["id"])
	require.Equal(t, "login", detailData["category"])
	require.Equal(t, "req-login", detailData["request_id"])
	loginMetadata, ok := detailData["metadata"].(map[string]any)
	require.True(t, ok, "expected metadata object, got %T", detailData["metadata"])
	require.Equal(t, "email", loginMetadata["provider"])

	bindingMetadata, ok := failureItem["metadata"].(map[string]any)
	require.True(t, ok, "expected metadata object, got %T", failureItem["metadata"])
	owner, ok := bindingMetadata["owner"].(map[string]any)
	require.True(t, ok, "expected owner object, got %T", bindingMetadata["owner"])
	require.Equal(t, float64(userID), owner["user_id"])
}

func seedAuditEvent(t *testing.T, stack *integrationStack, event model.AuditEvent) model.AuditEvent {
	t.Helper()
	require.NoError(t, stack.DB.Create(&event).Error)
	return event
}

func formatUint(value uint64) string {
	return strconv.FormatUint(value, 10)
}

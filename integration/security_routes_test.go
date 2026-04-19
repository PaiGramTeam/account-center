//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/casbin"
	"paigram/internal/model"
	"paigram/internal/response"
)

func TestAuthPasswordResetRoutesReachableWhenRateLimitEnabled(t *testing.T) {
	stack := newIntegrationStack(t)

	userID, _, _, email, password := registerVerifyAndLogin(t, stack, "password-reset")

	forgotRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/forgot-password", map[string]any{
		"email": email,
	}, nil)
	require.Equal(t, http.StatusOK, forgotRes.Code, forgotRes.Body.String())

	var resetTokenCount int64
	require.NoError(t, stack.DB.Model(&model.PasswordResetToken{}).Where("user_id = ?", userID).Count(&resetTokenCount).Error)
	assert.Equal(t, int64(1), resetTokenCount)

	resetRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/reset-password", map[string]any{
		"token":        "invalid-token",
		"new_password": password + "-new",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resetRes.Code, resetRes.Body.String())
	assert.Equal(t, "INVALID_TOKEN", decodeErrorCode(t, resetRes))
}

func TestProtectedSecurityRoutesReachableForAuthenticatedSelf(t *testing.T) {
	stack := newIntegrationStack(t)

	userID, accessToken, _, email, password := registerVerifyAndLogin(t, stack, "security-self")
	headers := authHeaders(accessToken)

	addEmailRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/me/emails", map[string]any{
		"email": fmt.Sprintf("alias-%d@example.com", userID),
	}, headers)
	require.Equal(t, http.StatusCreated, addEmailRes.Code, addEmailRes.Body.String())

	sessionsRes := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me/sessions", nil, headers)
	require.Equal(t, http.StatusOK, sessionsRes.Code, sessionsRes.Body.String())

	changePasswordRes := performJSONRequest(t, stack.Router, http.MethodPut, "/api/v1/me/security/password", map[string]any{
		"old_password": password,
		"new_password": password + "-updated",
	}, headers)
	require.Equal(t, http.StatusOK, changePasswordRes.Code, changePasswordRes.Body.String())

	loginRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    email,
		"password": password + "-updated",
	}, map[string]string{"User-Agent": "IntegrationSecurityRoutes/1.0"})
	require.Equal(t, http.StatusOK, loginRes.Code, loginRes.Body.String())
}

func TestSensitiveSecurityRoutesRequireFreshSession(t *testing.T) {
	stack := newIntegrationStack(t)

	_, accessToken, refreshToken, _, password := registerVerifyAndLogin(t, stack, "freshness")
	session := requireSessionForRefreshToken(t, stack.DB, refreshToken)
	require.NoError(t, stack.DB.Model(&model.UserSession{}).Where("id = ?", session.ID).Update("created_at", time.Now().UTC().Add(-10*time.Minute)).Error)

	staleRes := performJSONRequest(t, stack.Router, http.MethodPut, "/api/v1/me/security/password", map[string]any{
		"old_password": password,
		"new_password": password + "-stale",
	}, authHeaders(accessToken))
	require.Equal(t, http.StatusForbidden, staleRes.Code, staleRes.Body.String())
	assert.Equal(t, "SESSION_NOT_FRESH", decodeErrorCode(t, staleRes))
}

func TestLegacyBotAuthorizationRouteStaysNotFoundForAuthenticatedUsers(t *testing.T) {
	stack := newIntegrationStack(t)

	_, accessToken, _, _, _ := registerVerifyAndLogin(t, stack, "legacy-botauth-not-found")

	for _, tc := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/api/v1/bot-authorizations"},
		{method: http.MethodPost, path: "/api/v1/bot-authorizations"},
		{method: http.MethodGet, path: "/api/v1/bot-authorizations/1"},
		{method: http.MethodDelete, path: "/api/v1/bot-authorizations/1"},
	} {
		res := performJSONRequest(t, stack.Router, tc.method, tc.path, nil, authHeaders(accessToken))
		require.Equal(t, http.StatusNotFound, res.Code, "%s %s => %s", tc.method, tc.path, res.Body.String())
	}
}

func TestCrossUserRoutesRequirePermissions(t *testing.T) {
	stack := newIntegrationStack(t)

	viewerID, viewerAccessToken, _, _, _ := registerVerifyAndLogin(t, stack, "permission-viewer")
	targetID, _, _, _, _ := registerVerifyAndLogin(t, stack, "permission-target")

	headers := authHeaders(viewerAccessToken)

	t.Logf("[TEST] viewerID=%d, targetID=%d", viewerID, targetID)

	for _, path := range []string{
		fmt.Sprintf("/api/v1/admin/users/%d", targetID),
		fmt.Sprintf("/api/v1/admin/users/%d/roles", targetID),
		fmt.Sprintf("/api/v1/admin/users/%d/permissions", targetID),
		fmt.Sprintf("/api/v1/admin/users/%d/audit-logs", targetID),
		fmt.Sprintf("/api/v1/admin/users/%d/login-logs", targetID),
	} {
		res := performJSONRequest(t, stack.Router, http.MethodGet, path, nil, headers)
		require.Equal(t, http.StatusForbidden, res.Code, "%s => %s", path, res.Body.String())
		assert.Equal(t, "FORBIDDEN", decodeErrorCode(t, res))
	}

	t.Logf("[TEST] Before granting permissions to viewerID=%d", viewerID)
	grantPermissionsToUser(t, stack, viewerID,
		model.PermUserRead,
		model.PermRoleRead,
		model.PermPermissionRead,
		model.PermAuditRead,
	)

	for _, path := range []string{
		fmt.Sprintf("/api/v1/admin/users/%d", targetID),
		fmt.Sprintf("/api/v1/admin/users/%d/roles", targetID),
		fmt.Sprintf("/api/v1/admin/users/%d/permissions", targetID),
		fmt.Sprintf("/api/v1/admin/users/%d/audit-logs", targetID),
		fmt.Sprintf("/api/v1/admin/users/%d/login-logs", targetID),
	} {
		t.Logf("[TEST] Testing access to %s after granting permissions", path)
		res := performJSONRequest(t, stack.Router, http.MethodGet, path, nil, headers)
		if res.Code != http.StatusOK {
			t.Logf("[TEST] FAILED: Expected 200, got %d. Response: %s", res.Code, res.Body.String())
		}
		require.Equal(t, http.StatusOK, res.Code, "%s => %s", path, res.Body.String())
	}
}

func TestAdminRoutesRequireAdminRole(t *testing.T) {
	stack := newIntegrationStack(t)

	actorID, actorAccessToken, _, _, _ := registerVerifyAndLogin(t, stack, "admin-actor")
	targetID, _, _, targetEmail, _ := registerVerifyAndLogin(t, stack, "admin-target")

	resetPath := fmt.Sprintf("/api/v1/admin/users/%d/reset-password", targetID)
	body := map[string]any{
		"new_password":        "ResetByAdmin123!",
		"invalidate_sessions": true,
	}
	denied := performJSONRequest(t, stack.Router, http.MethodPost, resetPath, body, authHeaders(actorAccessToken))
	require.Equal(t, http.StatusForbidden, denied.Code, denied.Body.String())

	grantAdminRoleToUser(t, stack, actorID)

	allowed := performJSONRequest(t, stack.Router, http.MethodPost, resetPath, body, authHeaders(actorAccessToken))
	require.Equal(t, http.StatusOK, allowed.Code, allowed.Body.String())

	loginRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    targetEmail,
		"password": "ResetByAdmin123!",
	}, map[string]string{"User-Agent": "IntegrationSecurityRoutes/1.0"})
	require.Equal(t, http.StatusOK, loginRes.Code, loginRes.Body.String())
}

func TestRoleCatalogRoutesRequireExpectedPrivileges(t *testing.T) {
	stack := newIntegrationStack(t)

	actorID, actorAccessToken, _, _, _ := registerVerifyAndLogin(t, stack, "catalog-actor")
	headers := authHeaders(actorAccessToken)

	for _, path := range []string{"/api/v1/admin/roles", "/api/v1/roles", "/api/v1/permissions"} {
		res := performJSONRequest(t, stack.Router, http.MethodGet, path, nil, headers)
		expected := http.StatusForbidden
		if path == "/api/v1/roles" || path == "/api/v1/permissions" {
			expected = http.StatusNotFound
		}
		require.Equal(t, expected, res.Code, "%s => %s", path, res.Body.String())
	}

	grantPermissionsToUser(t, stack, actorID, model.PermRoleRead)

	listRolesAllowed := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/admin/roles", nil, headers)
	require.Equal(t, http.StatusOK, listRolesAllowed.Code, listRolesAllowed.Body.String())

	createRoleDenied := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/admin/roles", map[string]any{
		"name":         fmt.Sprintf("ops-%d", time.Now().UnixNano()),
		"display_name": "Operations",
		"description":  "ops role",
	}, headers)
	require.Equal(t, http.StatusForbidden, createRoleDenied.Code, createRoleDenied.Body.String())

	for _, path := range []string{"/api/v1/roles", "/api/v1/permissions"} {
		res := performJSONRequest(t, stack.Router, http.MethodPost, path, map[string]any{"name": "legacy"}, headers)
		require.Equal(t, http.StatusNotFound, res.Code, "%s => %s", path, res.Body.String())
	}

	grantPermissionsToUser(t, stack, actorID, model.BuildPermissionName(model.ResourceRole, model.ActionCreate))

	createRoleAllowed := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/admin/roles", map[string]any{
		"name":         fmt.Sprintf("ops-%d", time.Now().UnixNano()),
		"display_name": "Operations",
		"description":  "ops role",
	}, headers)
	require.Equal(t, http.StatusOK, createRoleAllowed.Code, createRoleAllowed.Body.String())
}

func TestRoleManagementRoutesRequireRoleManagePermission(t *testing.T) {
	stack := newIntegrationStack(t)

	actorID, actorAccessToken, _, _, _ := registerVerifyAndLogin(t, stack, "authority-manager")
	headers := authHeaders(actorAccessToken)

	customRole := model.Role{
		Name:        fmt.Sprintf("custom-manager-%d", time.Now().UnixNano()),
		DisplayName: "Custom Manager",
		Description: "custom manager role",
	}
	require.NoError(t, stack.DB.Create(&customRole).Error)
	require.NoError(t, stack.DB.Create(&model.UserRole{UserID: actorID, RoleID: customRole.ID, GrantedBy: actorID}).Error)

	permission := model.Permission{
		Name:        fmt.Sprintf("custom:grant:%d", time.Now().UnixNano()),
		Resource:    model.ResourceUser,
		Action:      model.ActionDelete,
		Description: "dangerous custom permission",
	}
	require.NoError(t, stack.DB.Create(&permission).Error)

	assignPermissionRes := performJSONRequest(t, stack.Router, http.MethodPut,
		fmt.Sprintf("/api/v1/admin/roles/%d/permissions", customRole.ID), map[string]any{
			"permission_ids": []uint64{permission.ID},
		}, headers)
	require.Equal(t, http.StatusForbidden, assignPermissionRes.Code, assignPermissionRes.Body.String())

	var rolePermissionCount int64
	require.NoError(t, stack.DB.Model(&model.RolePermission{}).Where("role_id = ? AND permission_id = ?", customRole.ID, permission.ID).Count(&rolePermissionCount).Error)
	assert.Equal(t, int64(0), rolePermissionCount)

	privilegedRole := model.Role{
		Name:        fmt.Sprintf("privileged-custom-%d", time.Now().UnixNano()),
		DisplayName: "Privileged Custom",
		Description: "privileged custom role",
	}
	require.NoError(t, stack.DB.Create(&privilegedRole).Error)

	grantPermissionsToUser(t, stack, actorID, model.BuildPermissionName(model.ResourceRole, model.ActionManage))

	assignPermissionAllowed := performJSONRequest(t, stack.Router, http.MethodPut,
		fmt.Sprintf("/api/v1/admin/roles/%d/permissions", customRole.ID), map[string]any{
			"permission_ids": []uint64{permission.ID},
		}, headers)
	require.Equal(t, http.StatusOK, assignPermissionAllowed.Code, assignPermissionAllowed.Body.String())

	require.NoError(t, stack.DB.Model(&model.RolePermission{}).Where("role_id = ? AND permission_id = ?", customRole.ID, permission.ID).Count(&rolePermissionCount).Error)
	assert.Equal(t, int64(1), rolePermissionCount)

	addSelfRes := performJSONRequest(t, stack.Router, http.MethodPut,
		fmt.Sprintf("/api/v1/admin/roles/%d/users", privilegedRole.ID), map[string]any{
			"user_ids": []uint64{actorID},
		}, headers)
	require.Equal(t, http.StatusOK, addSelfRes.Code, addSelfRes.Body.String())

	var privilegedAssignmentCount int64
	require.NoError(t, stack.DB.Model(&model.UserRole{}).Where("role_id = ? AND user_id = ?", privilegedRole.ID, actorID).Count(&privilegedAssignmentCount).Error)
	assert.Equal(t, int64(1), privilegedAssignmentCount)
}

func TestUserSessionAndSecuritySummaryRoutesRequirePermissions(t *testing.T) {
	stack := newIntegrationStack(t)

	viewerID, viewerAccessToken, _, _, _ := registerVerifyAndLogin(t, stack, "session-viewer")
	targetID, _, _, _, _ := registerVerifyAndLogin(t, stack, "session-target")

	var targetSession model.UserSession
	require.NoError(t, stack.DB.Where("user_id = ?", targetID).Order("created_at DESC").First(&targetSession).Error)

	headers := authHeaders(viewerAccessToken)

	for _, path := range []string{
		fmt.Sprintf("/api/v1/admin/users/%d/sessions", targetID),
		fmt.Sprintf("/api/v1/admin/users/%d/security-summary", targetID),
	} {
		res := performJSONRequest(t, stack.Router, http.MethodGet, path, nil, headers)
		require.Equal(t, http.StatusForbidden, res.Code, "%s => %s", path, res.Body.String())
	}

	deleteDenied := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/admin/users/%d/sessions/%d", targetID, targetSession.ID), nil, headers)
	require.Equal(t, http.StatusForbidden, deleteDenied.Code, deleteDenied.Body.String())

	grantPermissionsToUser(t, stack, viewerID, model.PermUserRead, model.BuildPermissionName(model.ResourceSession, model.ActionRead), model.BuildPermissionName(model.ResourceSession, model.ActionDelete))

	sessionsRes := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d/sessions", targetID), nil, headers)
	require.Equal(t, http.StatusOK, sessionsRes.Code, sessionsRes.Body.String())

	var sessionsPayload response.Response
	require.NoError(t, json.Unmarshal(sessionsRes.Body.Bytes(), &sessionsPayload))
	sessionsData, ok := sessionsPayload.Data.(map[string]any)
	require.True(t, ok, "expected sessions response data map, got %T", sessionsPayload.Data)
	items, ok := sessionsData["items"].([]any)
	require.True(t, ok, "expected sessions items slice, got %T", sessionsData["items"])
	require.NotEmpty(t, items)

	summaryRes := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d/security-summary", targetID), nil, headers)
	require.Equal(t, http.StatusOK, summaryRes.Code, summaryRes.Body.String())
	summaryData := decodeResponseData(t, summaryRes)
	assert.Equal(t, float64(targetID), summaryData["user_id"])
	assert.Contains(t, summaryData, "active_session_count")
	assert.Contains(t, summaryData, "device_count")
	assert.Contains(t, summaryData, "failed_logins_last_30_days")

	revokeRes := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/admin/users/%d/sessions/%d", targetID, targetSession.ID), nil, headers)
	require.Equal(t, http.StatusOK, revokeRes.Code, revokeRes.Body.String())

	var revokedSession model.UserSession
	require.NoError(t, stack.DB.First(&revokedSession, targetSession.ID).Error)
	assert.True(t, revokedSession.RevokedAt.Valid)
	assert.Equal(t, "revoked by admin", revokedSession.RevokedReason)
}

func TestSelfServiceLoginLogsAndSessionRoutes(t *testing.T) {
	stack := newIntegrationStack(t)

	userID, accessToken, refreshToken, _, _ := registerVerifyAndLogin(t, stack, "self-service")
	headers := authHeaders(accessToken)
	require.NoError(t, stack.DB.Create(&model.AuditLog{UserID: userID, Action: "session.self_viewed", Details: "self activity", IP: "192.0.2.30"}).Error)

	loginLogsRes := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me/activity-logs", nil, headers)
	require.Equal(t, http.StatusOK, loginLogsRes.Code, loginLogsRes.Body.String())

	loginLogsData := decodeResponseData(t, loginLogsRes)
	logItems, ok := loginLogsData["items"].([]any)
	require.True(t, ok, "expected login log items list, got %T", loginLogsData["items"])
	require.NotEmpty(t, logItems)

	firstLog, ok := logItems[0].(map[string]any)
	require.True(t, ok, "expected first login log entry map, got %T", logItems[0])
	assert.Equal(t, "session.self_viewed", firstLog["action"])
	assert.NotEmpty(t, firstLog["action"])

	otherUserID, _, _, _, _ := registerVerifyAndLogin(t, stack, "self-service-target")
	forbiddenLogsRes := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d/login-logs", otherUserID), nil, headers)
	require.Equal(t, http.StatusForbidden, forbiddenLogsRes.Code, forbiddenLogsRes.Body.String())
	assert.Equal(t, "FORBIDDEN", decodeErrorCode(t, forbiddenLogsRes))

	grantPermissionsToUser(t, stack, userID, model.PermAuditRead)
	authorizedCrossUserLogsRes := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d/login-logs", otherUserID), nil, headers)
	require.Equal(t, http.StatusOK, authorizedCrossUserLogsRes.Code, authorizedCrossUserLogsRes.Body.String())

	currentSession := requireSessionForRefreshToken(t, stack.DB, refreshToken)
	revokeSelfRes := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/me/sessions/%d", currentSession.ID), nil, headers)
	require.Equal(t, http.StatusNoContent, revokeSelfRes.Code, revokeSelfRes.Body.String())

	var revokedSession model.UserSession
	require.NoError(t, stack.DB.First(&revokedSession, currentSession.ID).Error)
	assert.True(t, revokedSession.RevokedAt.Valid)
	assert.Equal(t, "revoked by user", revokedSession.RevokedReason)

	reuseRes := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me", nil, headers)
	require.Equal(t, http.StatusUnauthorized, reuseRes.Code, reuseRes.Body.String())
	assert.Equal(t, "SESSION_REVOKED", decodeErrorCode(t, reuseRes))
}

func TestUserManagementMutationRoutesRespectPermissionsAndRoles(t *testing.T) {
	stack := newIntegrationStack(t)

	actorID, actorAccessToken, _, _, _ := registerVerifyAndLogin(t, stack, "mutator")
	headers := authHeaders(actorAccessToken)

	memberRole := model.Role{
		Name:        fmt.Sprintf("member-%d", time.Now().UnixNano()),
		DisplayName: "Member",
		Description: "member role",
	}
	adminRole := model.Role{
		Name:        fmt.Sprintf("manager-%d", time.Now().UnixNano()),
		DisplayName: "Manager",
		Description: "manager role",
	}
	require.NoError(t, stack.DB.Create(&memberRole).Error)
	require.NoError(t, stack.DB.Create(&adminRole).Error)

	createBody := map[string]any{
		"email":              fmt.Sprintf("managed-%d@example.com", time.Now().UnixNano()),
		"display_name":       "Managed User",
		"password":           "ManagedPass123!",
		"primary_login_type": "email",
		"status":             "active",
		"locale":             "zh_CN",
		"roles":              []string{memberRole.Name},
	}

	createDenied := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/admin/users", createBody, headers)
	require.Equal(t, http.StatusForbidden, createDenied.Code, createDenied.Body.String())

	grantPermissionsToUser(t, stack, actorID, model.BuildPermissionName(model.ResourceUser, model.ActionCreate), model.BuildPermissionName(model.ResourceUser, model.ActionUpdate), model.PermRoleRead, model.PermPermissionRead, model.PermUserRead)

	createAllowed := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/admin/users", createBody, headers)
	require.Equal(t, http.StatusBadRequest, createAllowed.Code, createAllowed.Body.String())

	createBodyWithoutRoles := map[string]any{
		"email":              fmt.Sprintf("managed-%d@example.com", time.Now().UnixNano()),
		"display_name":       "Managed User",
		"password":           "ManagedPass123!",
		"primary_login_type": "email",
		"status":             "active",
		"locale":             "zh_CN",
	}

	createWithoutRolesAllowed := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/admin/users", createBodyWithoutRoles, headers)
	require.Equal(t, http.StatusCreated, createWithoutRolesAllowed.Code, createWithoutRolesAllowed.Body.String())
	createdUserData := decodeResponseData(t, createWithoutRolesAllowed)
	createdUserID := uint64(createdUserData["id"].(float64))
	assert.Equal(t, "zh_CN", createdUserData["locale"])

	getRolesRes := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d/roles", createdUserID), nil, headers)
	require.Equal(t, http.StatusOK, getRolesRes.Code, getRolesRes.Body.String())
	getRolesData := decodeResponseData(t, getRolesRes)
	roleItems, ok := getRolesData["items"].([]any)
	require.True(t, ok, "expected paginated role items, got %T", getRolesData["items"])
	require.Empty(t, roleItems)

	updateDeniedHeaders := authHeaders(actorAccessToken)
	updateDenied := performJSONRequest(t, stack.Router, http.MethodPatch, fmt.Sprintf("/api/v1/admin/users/%d", createdUserID), map[string]any{
		"display_name": "Managed User Updated",
		"locale":       "en_US",
		"roles":        []string{adminRole.Name},
	}, updateDeniedHeaders)
	require.Equal(t, http.StatusBadRequest, updateDenied.Code, updateDenied.Body.String())

	unchangedRolesRes := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d/roles", createdUserID), nil, headers)
	require.Equal(t, http.StatusOK, unchangedRolesRes.Code, unchangedRolesRes.Body.String())
	unchangedRolesData := decodeResponseData(t, unchangedRolesRes)
	unchangedRoleItems, ok := unchangedRolesData["items"].([]any)
	require.True(t, ok, "expected paginated role items, got %T", unchangedRolesData["items"])
	require.Empty(t, unchangedRoleItems)

	deleteDenied := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/admin/users/%d", createdUserID), nil, headers)
	require.Equal(t, http.StatusForbidden, deleteDenied.Code, deleteDenied.Body.String())

	grantPermissionsToUser(t, stack, actorID, model.BuildPermissionName(model.ResourceUser, model.ActionDelete))
	deleteAllowed := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/admin/users/%d", createdUserID), nil, headers)
	require.Equal(t, http.StatusNoContent, deleteAllowed.Code, deleteAllowed.Body.String())

	var deletedUser model.User
	require.NoError(t, stack.DB.Unscoped().First(&deletedUser, createdUserID).Error)
	assert.True(t, deletedUser.DeletedAt.Valid)
}

func TestTwoFactorLifecycle(t *testing.T) {
	stack := newIntegrationStack(t)

	userID, accessToken, _, _, password := registerVerifyAndLogin(t, stack, "twofa")
	headers := authHeaders(accessToken)

	enableRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/me/security/2fa/setup", map[string]any{
		"password": password,
	}, headers)
	require.Equal(t, http.StatusOK, enableRes.Code, enableRes.Body.String())
	enableData := decodeResponseData(t, enableRes)
	secret := enableData["secret"].(string)
	backupCodesRaw := enableData["backup_codes"].([]any)
	require.NotEmpty(t, backupCodesRaw)
	firstBackupCode := backupCodesRaw[0].(string)

	code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	confirmRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/me/security/2fa/confirm", map[string]any{
		"code": code,
	}, headers)
	require.Equal(t, http.StatusOK, confirmRes.Code, confirmRes.Body.String())

	regenRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/me/security/2fa/backup-codes/regenerate", map[string]any{
		"password": password,
	}, headers)
	require.Equal(t, http.StatusOK, regenRes.Code, regenRes.Body.String())
	regenData := decodeResponseData(t, regenRes)
	newBackupCodes := regenData["backup_codes"].([]any)
	require.Len(t, newBackupCodes, 10)
	assert.NotEqual(t, firstBackupCode, newBackupCodes[0].(string))

	disableCode, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	disableRes := performJSONRequest(t, stack.Router, http.MethodDelete, "/api/v1/me/security/2fa", map[string]any{
		"password": password,
		"code":     disableCode,
	}, headers)
	require.Equal(t, http.StatusOK, disableRes.Code, disableRes.Body.String())

	var twoFactorCount int64
	require.NoError(t, stack.DB.Model(&model.UserTwoFactor{}).Where("user_id = ?", userID).Count(&twoFactorCount).Error)
	assert.Zero(t, twoFactorCount)

	var auditCount int64
	require.NoError(t, stack.DB.Model(&model.AuditLog{}).Where("user_id = ? AND action IN ?", userID, []string{"2fa_enabled", "2fa_disabled", "2fa_backup_codes_regenerated"}).Count(&auditCount).Error)
	assert.Equal(t, int64(3), auditCount)
}

func TestTwoFactorRoutesRequireFreshSession(t *testing.T) {
	stack := newIntegrationStack(t)

	_, accessToken, refreshToken, _, password := registerVerifyAndLogin(t, stack, "twofa-stale")
	session := requireSessionForRefreshToken(t, stack.DB, refreshToken)
	require.NoError(t, stack.DB.Model(&model.UserSession{}).Where("id = ?", session.ID).Update("created_at", time.Now().UTC().Add(-10*time.Minute)).Error)

	res := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/me/security/2fa/setup", map[string]any{
		"password": password,
	}, authHeaders(accessToken))
	require.Equal(t, http.StatusForbidden, res.Code, res.Body.String())
	assert.Equal(t, "SESSION_NOT_FRESH", decodeErrorCode(t, res))
}

func registerVerifyAndLogin(t *testing.T, stack *integrationStack, prefix string) (uint64, string, string, string, string) {
	t.Helper()

	email := fmt.Sprintf("%s-%d@example.com", prefix, time.Now().UnixNano())
	password := "Password123!"

	registerRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":        email,
		"password":     password,
		"display_name": "Security Tester",
		"locale":       "en_US",
	}, nil)
	require.Equal(t, http.StatusCreated, registerRes.Code, registerRes.Body.String())
	registerData := decodeResponseData(t, registerRes)
	verificationToken := registerData["verification_token"].(string)

	verifyRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/verify-email", map[string]any{
		"email": email,
		"token": verificationToken,
	}, nil)
	require.Equal(t, http.StatusOK, verifyRes.Code, verifyRes.Body.String())

	loginRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    email,
		"password": password,
	}, map[string]string{"User-Agent": "IntegrationSecurityRoutes/1.0"})
	require.Equal(t, http.StatusOK, loginRes.Code, loginRes.Body.String())
	loginData := decodeResponseData(t, loginRes)

	userID := uint64(loginData["user_id"].(float64))
	accessToken := loginData["access_token"].(string)
	refreshToken := loginData["refresh_token"].(string)

	return userID, accessToken, refreshToken, email, password
}

func authHeaders(accessToken string) map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + accessToken,
		"User-Agent":    "IntegrationSecurityRoutes/1.0",
	}
}

func decodeErrorCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()

	var payload map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
	errorData, ok := payload["error"].(map[string]any)
	require.True(t, ok, "expected error map in response, got %T", payload["error"])
	code, _ := errorData["code"].(string)
	return code
}

func grantPermissionsToUser(t *testing.T, stack *integrationStack, userID uint64, permissionNames ...string) {
	t.Helper()

	roleName := fmt.Sprintf("test-role-%d-%d", userID, time.Now().UnixNano())
	role := model.Role{
		Name:        roleName,
		DisplayName: roleName,
		Description: "integration test role",
	}
	require.NoError(t, stack.DB.Create(&role).Error)
	t.Logf("[DEBUG] Created role: ID=%d, Name=%s", role.ID, role.Name)

	// Get Casbin enforcer
	enforcer := casbin.GetEnforcer()
	require.NotNil(t, enforcer, "Casbin enforcer should be initialized")

	for _, permName := range permissionNames {
		permission := model.Permission{
			Name:        permName,
			Resource:    permissionResource(permName),
			Action:      permissionAction(permName),
			Description: "integration test permission",
		}
		require.NoError(t, stack.DB.Where(model.Permission{Name: permName}).FirstOrCreate(&permission).Error)
		rolePermission := model.RolePermission{RoleID: role.ID, PermissionID: permission.ID}
		require.NoError(t, stack.DB.Where(&rolePermission).FirstOrCreate(&rolePermission).Error)

		// Create Casbin policies for the permission
		// Map permission names to (path, HTTP method) pairs
		policies := mapPermissionToPolicies(permName)

		for _, policy := range policies {
			added, err := enforcer.AddPolicy(fmt.Sprint(role.ID), policy.Path, policy.Method)
			require.NoError(t, err, "Failed to add Casbin policy for %s (%s %s): %v", permName, policy.Method, policy.Path, err)
			t.Logf("[DEBUG] Added Casbin policy: role=%d, path=%s, method=%s, added=%v", role.ID, policy.Path, policy.Method, added)
		}
	}

	userRole := model.UserRole{UserID: userID, RoleID: role.ID, GrantedBy: userID}
	require.NoError(t, stack.DB.Create(&userRole).Error)
	t.Logf("[DEBUG] Assigned role %d to user %d", role.ID, userID)

	// Verify the policies were actually added
	allPolicies := enforcer.GetPolicy()
	t.Logf("[DEBUG] Total Casbin policies in enforcer: %d", len(allPolicies))
	for i, p := range allPolicies {
		if len(p) >= 3 {
			t.Logf("[DEBUG] Policy %d: [%s, %s, %s]", i, p[0], p[1], p[2])
		}
	}
}

// PolicyRule represents a Casbin policy rule with path and HTTP method
type PolicyRule struct {
	Path   string
	Method string
}

// mapPermissionToPolicies maps permission names to Casbin policy rules (path + HTTP method)
func mapPermissionToPolicies(permName string) []PolicyRule {
	switch permName {
	case model.PermUserRead:
		return []PolicyRule{
			{"/api/v1/admin/users/*", "GET"},
		}
	case model.PermUserWrite:
		return []PolicyRule{
			{"/api/v1/admin/users", "POST"},
			{"/api/v1/admin/users/*", "PATCH"},
			{"/api/v1/admin/users/*", "PUT"},
		}
	case model.BuildPermissionName(model.ResourceUser, model.ActionCreate):
		return []PolicyRule{{"/api/v1/admin/users", "POST"}}
	case model.BuildPermissionName(model.ResourceUser, model.ActionUpdate):
		return []PolicyRule{{"/api/v1/admin/users/*", "PATCH"}, {"/api/v1/admin/users/*", "PUT"}}
	case model.PermUserDelete:
		return []PolicyRule{
			{"/api/v1/admin/users/*", "DELETE"},
		}
	case model.BuildPermissionName(model.ResourceUser, model.ActionDelete):
		return []PolicyRule{{"/api/v1/admin/users/*", "DELETE"}}
	case model.BuildPermissionName(model.ResourceUser, model.ActionList):
		return []PolicyRule{{"/api/v1/admin/users", "GET"}}
	case model.PermUserManage:
		return []PolicyRule{
			{"/api/v1/admin/users/*", "GET"},
			{"/api/v1/admin/users/*", "POST"},
			{"/api/v1/admin/users/*", "PATCH"},
			{"/api/v1/admin/users/*", "DELETE"},
		}
	case model.PermRoleRead:
		return []PolicyRule{
			{"/api/v1/admin/roles", "GET"},
			{"/api/v1/admin/roles/*", "GET"},
			{"/api/v1/admin/users/*/roles", "GET"},
		}
	case model.PermRoleWrite:
		return []PolicyRule{
			{"/api/v1/admin/roles", "POST"},
			{"/api/v1/admin/roles/*", "PATCH"},
			{"/api/v1/admin/roles/*", "PUT"},
		}
	case model.BuildPermissionName(model.ResourceRole, model.ActionCreate):
		return []PolicyRule{{"/api/v1/admin/roles", "POST"}}
	case model.BuildPermissionName(model.ResourceRole, model.ActionUpdate):
		return []PolicyRule{{"/api/v1/admin/roles/*", "PATCH"}, {"/api/v1/admin/roles/*", "PUT"}}
	case model.PermRoleDelete:
		return []PolicyRule{
			{"/api/v1/admin/roles/*", "DELETE"},
		}
	case model.BuildPermissionName(model.ResourceRole, model.ActionDelete):
		return []PolicyRule{{"/api/v1/admin/roles/*", "DELETE"}}
	case model.BuildPermissionName(model.ResourceRole, model.ActionList):
		return []PolicyRule{{"/api/v1/admin/roles", "GET"}}
	case model.PermRoleManage:
		return []PolicyRule{
			{"/api/v1/admin/roles/*/users", "PUT"},
			{"/api/v1/admin/roles/*/permissions", "PUT"},
		}
	case model.PermPermissionRead:
		return []PolicyRule{
			{"/api/v1/admin/users/*/permissions", "GET"},
			{"/api/v1/admin/roles/*/permissions", "GET"},
		}
	case model.BuildPermissionName(model.ResourceSession, model.ActionRead):
		return []PolicyRule{{"/api/v1/admin/users/*/sessions", "GET"}}
	case model.BuildPermissionName(model.ResourceSession, model.ActionDelete):
		return []PolicyRule{{"/api/v1/admin/users/*/sessions/*", "DELETE"}}
	case model.PermPermissionWrite:
		return nil
	case model.PermPermissionDelete:
		return nil
	case model.PermAuditRead:
		return []PolicyRule{
			{"/api/v1/admin/users/*/audit-logs", "GET"},
			{"/api/v1/admin/users/*/login-logs", "GET"},
			{"/api/v1/admin/audit-logs", "GET"},
			{"/api/v1/admin/audit-logs/*", "GET"},
		}
	default:
		// Fallback: derive from permission name
		resource := strings.Split(permName, ":")[0]
		action := strings.Split(permName, ":")[1]
		method := actionToHTTPMethod(action)
		return []PolicyRule{
			{fmt.Sprintf("/api/v1/%s/*", resource), method},
		}
	}
}

// actionToHTTPMethod converts permission action to HTTP method
func actionToHTTPMethod(action string) string {
	switch strings.ToLower(action) {
	case "read":
		return "GET"
	case "write":
		return "POST"
	case "delete":
		return "DELETE"
	case "manage":
		return "GET" // Default for manage, usually needs multiple methods
	default:
		return "GET"
	}
}

func grantAdminRoleToUser(t *testing.T, stack *integrationStack, userID uint64) {
	t.Helper()

	role := model.Role{
		Name:        model.RoleAdmin,
		DisplayName: "Admin",
		Description: "integration test admin role",
		IsSystem:    true,
	}
	require.NoError(t, stack.DB.Where(model.Role{Name: model.RoleAdmin}).FirstOrCreate(&role).Error)

	// Get Casbin enforcer
	enforcer := casbin.GetEnforcer()
	require.NotNil(t, enforcer, "Casbin enforcer should be initialized")

	// Grant admin all permissions via Casbin policies
	// Admin should have access to all routes
	adminPolicies := []PolicyRule{
		{"/api/v1/*", "GET"},
		{"/api/v1/*", "POST"},
		{"/api/v1/*", "PUT"},
		{"/api/v1/*", "PATCH"},
		{"/api/v1/*", "DELETE"},
	}

	for _, policy := range adminPolicies {
		_, err := enforcer.AddPolicy(fmt.Sprint(role.ID), policy.Path, policy.Method)
		require.NoError(t, err, "Failed to add Casbin policy for admin: %v", err)
	}

	userRole := model.UserRole{UserID: userID, RoleID: role.ID, GrantedBy: userID}
	require.NoError(t, stack.DB.Where(model.UserRole{UserID: userID, RoleID: role.ID}).Assign(model.UserRole{GrantedBy: userID}).FirstOrCreate(&userRole).Error)
}

func permissionResource(name string) string {
	parts := splitPermission(name)
	return parts[0]
}

func permissionAction(name string) string {
	parts := splitPermission(name)
	return parts[1]
}

func splitPermission(name string) []string {
	parts := strings.SplitN(name, ":", 2)
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return parts
	}
	return []string{"custom", "custom"}
}

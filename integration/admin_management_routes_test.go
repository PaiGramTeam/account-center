//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/model"
)

func TestAdminManagementRoutes(t *testing.T) {
	stack := newIntegrationStack(t)

	adminID, adminAccessToken, _, _, _ := registerVerifyAndLogin(t, stack, "admin-management-admin")
	viewerID, viewerAccessToken, _, _, _ := registerVerifyAndLogin(t, stack, "admin-management-viewer")
	targetID, _, _, targetEmail, _ := registerVerifyAndLogin(t, stack, "admin-management-target")
	grantAdminRoleToUser(t, stack, adminID)

	managedRole := model.Role{
		Name:        fmt.Sprintf("managed-role-%d", time.Now().UnixNano()),
		DisplayName: "Managed Role",
		Description: "role managed via admin routes",
	}
	require.NoError(t, stack.DB.Create(&managedRole).Error)
	secondaryRole := model.Role{
		Name:        fmt.Sprintf("secondary-role-%d", time.Now().UnixNano()),
		DisplayName: "Secondary Role",
		Description: "secondary role managed via admin routes",
	}
	require.NoError(t, stack.DB.Create(&secondaryRole).Error)

	permission := model.Permission{
		Name:        fmt.Sprintf("admin-test:read:%d", time.Now().UnixNano()),
		Resource:    model.ResourceUser,
		Action:      model.ActionRead,
		Description: "permission exposed via admin user permissions route",
	}
	require.NoError(t, stack.DB.Create(&permission).Error)
	require.NoError(t, stack.DB.Create(&model.RolePermission{RoleID: managedRole.ID, PermissionID: permission.ID}).Error)
	require.NoError(t, stack.DB.Create(&model.UserRole{UserID: targetID, RoleID: managedRole.ID, GrantedBy: adminID}).Error)
	require.NoError(t, stack.DB.Create(&model.AuditLog{UserID: targetID, Action: "profile.updated", Details: "admin changed profile", IP: "192.0.2.10"}).Error)
	require.NoError(t, stack.DB.Create(&model.LoginLog{UserID: targetID, LoginType: model.LoginTypeEmail, IP: "192.0.2.11", UserAgent: "IntegrationSecurityRoutes/1.0", Device: "Chrome on Windows", Location: "Test Lab", Status: "failed", FailureReason: "bad password"}).Error)

	var targetSession model.UserSession
	require.NoError(t, stack.DB.Where("user_id = ?", targetID).Order("created_at DESC").First(&targetSession).Error)

	targetHeaders := authHeaders(adminAccessToken)

	t.Run("non-admin callers are denied", func(t *testing.T) {
		for _, tc := range []struct {
			method string
			path   string
			body   any
		}{
			{method: http.MethodGet, path: "/api/v1/admin/users"},
			{method: http.MethodPost, path: "/api/v1/admin/users", body: map[string]any{"email": fmt.Sprintf("denied-%d@example.com", time.Now().UnixNano()), "password": "Password123!", "display_name": "Denied User", "primary_login_type": "email", "status": "active"}},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/admin/users/%d", targetID)},
			{method: http.MethodPatch, path: fmt.Sprintf("/api/v1/admin/users/%d", targetID), body: map[string]any{"display_name": "Denied Rename"}},
			{method: http.MethodPatch, path: fmt.Sprintf("/api/v1/admin/users/%d/status", targetID), body: map[string]any{"status": "suspended"}},
			{method: http.MethodPost, path: fmt.Sprintf("/api/v1/admin/users/%d/reset-password", targetID), body: map[string]any{"new_password": "ResetByAdmin123!", "invalidate_sessions": true}},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/admin/users/%d/audit-logs", targetID)},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/admin/users/%d/roles", targetID)},
			{method: http.MethodPut, path: fmt.Sprintf("/api/v1/admin/users/%d/roles", targetID), body: map[string]any{"role_ids": []uint64{managedRole.ID}, "primary_role_id": managedRole.ID}},
			{method: http.MethodPatch, path: fmt.Sprintf("/api/v1/admin/users/%d/primary-role", targetID), body: map[string]any{"primary_role_id": managedRole.ID}},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/admin/users/%d/permissions", targetID)},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/admin/users/%d/sessions", targetID)},
			{method: http.MethodDelete, path: fmt.Sprintf("/api/v1/admin/users/%d/sessions/%d", targetID, targetSession.ID)},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/admin/users/%d/security-summary", targetID)},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/admin/users/%d/login-logs", targetID)},
			{method: http.MethodGet, path: "/api/v1/admin/roles"},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/admin/roles/%d", managedRole.ID)},
			{method: http.MethodPatch, path: fmt.Sprintf("/api/v1/admin/roles/%d", managedRole.ID), body: map[string]any{"description": "denied patch"}},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/admin/roles/%d/users", managedRole.ID)},
			{method: http.MethodPut, path: fmt.Sprintf("/api/v1/admin/roles/%d/users", managedRole.ID), body: map[string]any{"user_ids": []uint64{viewerID}}},
		} {
			resp := performJSONRequest(t, stack.Router, tc.method, tc.path, tc.body, authHeaders(viewerAccessToken))
			require.Equal(t, http.StatusForbidden, resp.Code, "%s %s should require admin role: %s", tc.method, tc.path, resp.Body.String())
		}
	})

	t.Run("admins can manage users and role assignments through admin routes", func(t *testing.T) {
		createdEmail := fmt.Sprintf("created-admin-user-%d@example.com", time.Now().UnixNano())
		createUserResp := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/admin/users", map[string]any{
			"email":              createdEmail,
			"password":           "Password123!",
			"display_name":       "Created By Admin",
			"primary_login_type": "email",
			"status":             "active",
		}, targetHeaders)
		require.Equal(t, http.StatusCreated, createUserResp.Code, createUserResp.Body.String())
		createdUserData := decodeResponseData(t, createUserResp)
		createdUserID := uint64(createdUserData["id"].(float64))

		rejectProviderPrimaryResp := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/admin/users", map[string]any{
			"email":              fmt.Sprintf("created-provider-user-%d@example.com", time.Now().UnixNano()),
			"password":           "Password123!",
			"display_name":       "Rejected Provider Primary",
			"primary_login_type": "github",
			"status":             "active",
		}, targetHeaders)
		require.Equal(t, http.StatusBadRequest, rejectProviderPrimaryResp.Code, rejectProviderPrimaryResp.Body.String())
		assert.Contains(t, rejectProviderPrimaryResp.Body.String(), "primary_login_type=email is required")

		listUsersResp := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/admin/users", nil, targetHeaders)
		require.Equal(t, http.StatusOK, listUsersResp.Code, listUsersResp.Body.String())
		listUsersData := decodeResponseData(t, listUsersResp)
		listUsers, ok := listUsersData["items"].([]any)
		require.True(t, ok, "expected admin users items list, got %T", listUsersData["items"])
		assert.NotEmpty(t, listUsers)

		getUserResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d", targetID), nil, targetHeaders)
		require.Equal(t, http.StatusOK, getUserResp.Code, getUserResp.Body.String())
		getUserData := decodeResponseData(t, getUserResp)
		assert.Equal(t, targetEmail, getUserData["primary_email"])

		updateUserResp := performJSONRequest(t, stack.Router, http.MethodPatch, fmt.Sprintf("/api/v1/admin/users/%d", targetID), map[string]any{
			"display_name": "Admin Updated Target",
			"bio":          "updated by admin route",
		}, targetHeaders)
		require.Equal(t, http.StatusOK, updateUserResp.Code, updateUserResp.Body.String())
		updatedUserData := decodeResponseData(t, updateUserResp)
		assert.Equal(t, "Admin Updated Target", updatedUserData["display_name"])

		updateStatusResp := performJSONRequest(t, stack.Router, http.MethodPatch, fmt.Sprintf("/api/v1/admin/users/%d/status", createdUserID), map[string]any{
			"status": "suspended",
		}, targetHeaders)
		require.Equal(t, http.StatusOK, updateStatusResp.Code, updateStatusResp.Body.String())
		updateStatusData := decodeResponseData(t, updateStatusResp)
		assert.Equal(t, string(model.UserStatusSuspended), updateStatusData["status"])

		auditResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d/audit-logs", targetID), nil, targetHeaders)
		require.Equal(t, http.StatusOK, auditResp.Code, auditResp.Body.String())
		auditData := decodeResponseData(t, auditResp)
		auditLogs, ok := auditData["items"].([]any)
		require.True(t, ok, "expected audit log items list, got %T", auditData["items"])
		assert.NotEmpty(t, auditLogs)

		userRolesResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d/roles", targetID), nil, targetHeaders)
		require.Equal(t, http.StatusOK, userRolesResp.Code, userRolesResp.Body.String())
		userRolesData := decodeResponseData(t, userRolesResp)
		userRoles, ok := userRolesData["items"].([]any)
		require.True(t, ok, "expected user role items list, got %T", userRolesData["items"])
		assert.NotEmpty(t, userRoles)

		replaceRolesResp := performJSONRequest(t, stack.Router, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/roles", targetID), map[string]any{
			"role_ids":        []uint64{managedRole.ID, secondaryRole.ID},
			"primary_role_id": secondaryRole.ID,
		}, targetHeaders)
		require.Equal(t, http.StatusOK, replaceRolesResp.Code, replaceRolesResp.Body.String())
		targetUser := model.User{}
		require.NoError(t, stack.DB.First(&targetUser, targetID).Error)
		require.True(t, targetUser.PrimaryRoleID.Valid)
		assert.Equal(t, int64(secondaryRole.ID), targetUser.PrimaryRoleID.Int64)
		var assignments []model.UserRole
		require.NoError(t, stack.DB.Where("user_id = ?", targetID).Order("role_id ASC").Find(&assignments).Error)
		require.Len(t, assignments, 2)

		patchPrimaryRoleResp := performJSONRequest(t, stack.Router, http.MethodPatch, fmt.Sprintf("/api/v1/admin/users/%d/primary-role", targetID), map[string]any{
			"primary_role_id": managedRole.ID,
		}, targetHeaders)
		require.Equal(t, http.StatusOK, patchPrimaryRoleResp.Code, patchPrimaryRoleResp.Body.String())
		targetUser = model.User{}
		require.NoError(t, stack.DB.First(&targetUser, targetID).Error)
		require.True(t, targetUser.PrimaryRoleID.Valid)
		assert.Equal(t, int64(managedRole.ID), targetUser.PrimaryRoleID.Int64)

		invalidPrimaryRoleResp := performJSONRequest(t, stack.Router, http.MethodPatch, fmt.Sprintf("/api/v1/admin/users/%d/primary-role", targetID), map[string]any{
			"primary_role_id": uint64(99999999),
		}, targetHeaders)
		require.Equal(t, http.StatusUnprocessableEntity, invalidPrimaryRoleResp.Code, invalidPrimaryRoleResp.Body.String())

		clearPrimaryRoleResp := performJSONRequest(t, stack.Router, http.MethodPatch, fmt.Sprintf("/api/v1/admin/users/%d/primary-role", targetID), map[string]any{
			"primary_role_id": nil,
		}, targetHeaders)
		require.Equal(t, http.StatusOK, clearPrimaryRoleResp.Code, clearPrimaryRoleResp.Body.String())
		targetUser = model.User{}
		require.NoError(t, stack.DB.First(&targetUser, targetID).Error)
		assert.False(t, targetUser.PrimaryRoleID.Valid)

		userPermissionsResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d/permissions", targetID), nil, targetHeaders)
		require.Equal(t, http.StatusOK, userPermissionsResp.Code, userPermissionsResp.Body.String())
		userPermissionsData := decodeResponseData(t, userPermissionsResp)
		permissionItems, ok := userPermissionsData["items"].([]any)
		require.True(t, ok, "expected permission items list, got %T", userPermissionsData["items"])
		assert.NotEmpty(t, permissionItems)

		sessionsResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d/sessions", targetID), nil, targetHeaders)
		require.Equal(t, http.StatusOK, sessionsResp.Code, sessionsResp.Body.String())
		sessionsData := decodeResponseData(t, sessionsResp)
		sessionItems, ok := sessionsData["items"].([]any)
		require.True(t, ok, "expected session items list, got %T", sessionsData["items"])
		assert.NotEmpty(t, sessionItems)

		revokeSessionResp := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/admin/users/%d/sessions/%d", targetID, targetSession.ID), nil, targetHeaders)
		require.Equal(t, http.StatusOK, revokeSessionResp.Code, revokeSessionResp.Body.String())
		var revokedSession model.UserSession
		require.NoError(t, stack.DB.Unscoped().First(&revokedSession, targetSession.ID).Error)
		assert.True(t, revokedSession.RevokedAt.Valid)

		securitySummaryResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d/security-summary", targetID), nil, targetHeaders)
		require.Equal(t, http.StatusOK, securitySummaryResp.Code, securitySummaryResp.Body.String())
		securitySummaryData := decodeResponseData(t, securitySummaryResp)
		assert.Equal(t, float64(targetID), securitySummaryData["user_id"])

		loginLogsResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d/login-logs", targetID), nil, targetHeaders)
		require.Equal(t, http.StatusOK, loginLogsResp.Code, loginLogsResp.Body.String())
		loginLogsData := decodeResponseData(t, loginLogsResp)
		loginLogs, ok := loginLogsData["items"].([]any)
		require.True(t, ok, "expected login log items list, got %T", loginLogsData["items"])
		assert.NotEmpty(t, loginLogs)

		resetResp := performJSONRequest(t, stack.Router, http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/reset-password", targetID), map[string]any{
			"new_password":        "ResetByAdmin123!",
			"invalidate_sessions": true,
		}, targetHeaders)
		require.Equal(t, http.StatusOK, resetResp.Code, resetResp.Body.String())

		listRolesResp := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/admin/roles", nil, targetHeaders)
		require.Equal(t, http.StatusOK, listRolesResp.Code, listRolesResp.Body.String())

		getRoleResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/roles/%d", managedRole.ID), nil, targetHeaders)
		require.Equal(t, http.StatusOK, getRoleResp.Code, getRoleResp.Body.String())

		patchRoleResp := performJSONRequest(t, stack.Router, http.MethodPatch, fmt.Sprintf("/api/v1/admin/roles/%d", managedRole.ID), map[string]any{
			"description": "patched via admin route",
		}, targetHeaders)
		require.Equal(t, http.StatusOK, patchRoleResp.Code, patchRoleResp.Body.String())
		var patchedRole model.Role
		require.NoError(t, stack.DB.First(&patchedRole, managedRole.ID).Error)
		assert.Equal(t, "patched via admin route", patchedRole.Description)

		roleUsersResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/roles/%d/users", managedRole.ID), nil, targetHeaders)
		require.Equal(t, http.StatusOK, roleUsersResp.Code, roleUsersResp.Body.String())
		var roleUsersResult map[string]any
		decodeJSON(t, roleUsersResp, &roleUsersResult)
		roleUsers, ok := roleUsersResult["data"].([]any)
		require.True(t, ok, "expected role users array, got %T", roleUsersResult["data"])
		require.Len(t, roleUsers, 1)

		replaceUsersResp := performJSONRequest(t, stack.Router, http.MethodPut, fmt.Sprintf("/api/v1/admin/roles/%d/users", managedRole.ID), map[string]any{
			"user_ids": []uint64{viewerID},
		}, targetHeaders)
		require.Equal(t, http.StatusOK, replaceUsersResp.Code, replaceUsersResp.Body.String())

		var updatedAssignments []model.UserRole
		require.NoError(t, stack.DB.Where("role_id = ?", managedRole.ID).Order("user_id ASC").Find(&updatedAssignments).Error)
		require.Len(t, updatedAssignments, 1)
		assert.Equal(t, viewerID, updatedAssignments[0].UserID)

		loginResp := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
			"email":    targetEmail,
			"password": "ResetByAdmin123!",
		}, map[string]string{"User-Agent": "IntegrationSecurityRoutes/1.0"})
		require.Equal(t, http.StatusOK, loginResp.Code, loginResp.Body.String())

		deleteCreatedUserResp := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/admin/users/%d?hard_delete=true", createdUserID), nil, targetHeaders)
		require.Equal(t, http.StatusNoContent, deleteCreatedUserResp.Code, deleteCreatedUserResp.Body.String())
		var deletedCount int64
		require.NoError(t, stack.DB.Unscoped().Model(&model.User{}).Where("id = ?", createdUserID).Count(&deletedCount).Error)
		assert.Equal(t, int64(0), deletedCount)
	})
}

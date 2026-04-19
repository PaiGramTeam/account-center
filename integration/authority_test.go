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

func TestAdminRoleManagementIntegration(t *testing.T) {
	stack := newIntegrationStack(t)

	adminID, adminToken, _, _, _ := registerVerifyAndLogin(t, stack, "authority-admin")
	grantAdminRoleToUser(t, stack, adminID)
	headers := authHeaders(adminToken)

	t.Run("role management", func(t *testing.T) {
		createResp := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/admin/roles", map[string]any{
			"name":         fmt.Sprintf("ops-%d", time.Now().UnixNano()),
			"display_name": "Operations",
			"description":  "ops role",
		}, headers)
		require.Equal(t, http.StatusOK, createResp.Code, createResp.Body.String())
		created := decodeResponseData(t, createResp)
		roleID := uint64(created["id"].(float64))

		listResp := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/admin/roles?page=1&page_size=10", nil, headers)
		require.Equal(t, http.StatusOK, listResp.Code, listResp.Body.String())

		getResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/roles/%d", roleID), nil, headers)
		require.Equal(t, http.StatusOK, getResp.Code, getResp.Body.String())

		updateResp := performJSONRequest(t, stack.Router, http.MethodPatch, fmt.Sprintf("/api/v1/admin/roles/%d", roleID), map[string]any{
			"display_name": "Operations Updated",
		}, headers)
		require.Equal(t, http.StatusOK, updateResp.Code, updateResp.Body.String())

		deleteResp := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/admin/roles/%d", roleID), nil, headers)
		require.Equal(t, http.StatusOK, deleteResp.Code, deleteResp.Body.String())
	})

	t.Run("role permissions and users", func(t *testing.T) {
		role := model.Role{Name: fmt.Sprintf("delegated-%d", time.Now().UnixNano()), DisplayName: "Delegated Role"}
		permission := model.Permission{Name: fmt.Sprintf("custom:read:%d", time.Now().UnixNano()), Resource: model.ResourceUser, Action: model.ActionRead}
		targetUserID, _, _, _, _ := registerVerifyAndLogin(t, stack, "authority-target")
		require.NoError(t, stack.DB.Create(&role).Error)
		require.NoError(t, stack.DB.Create(&permission).Error)

		putPermissionsResp := performJSONRequest(t, stack.Router, http.MethodPut, fmt.Sprintf("/api/v1/admin/roles/%d/permissions", role.ID), map[string]any{
			"permission_ids": []uint64{permission.ID},
		}, headers)
		require.Equal(t, http.StatusOK, putPermissionsResp.Code, putPermissionsResp.Body.String())

		getPermissionsResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/roles/%d/permissions", role.ID), nil, headers)
		require.Equal(t, http.StatusOK, getPermissionsResp.Code, getPermissionsResp.Body.String())

		putUsersResp := performJSONRequest(t, stack.Router, http.MethodPut, fmt.Sprintf("/api/v1/admin/roles/%d/users", role.ID), map[string]any{
			"user_ids": []uint64{targetUserID},
		}, headers)
		require.Equal(t, http.StatusOK, putUsersResp.Code, putUsersResp.Body.String())

		getUsersResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/roles/%d/users", role.ID), nil, headers)
		require.Equal(t, http.StatusOK, getUsersResp.Code, getUsersResp.Body.String())

		var count int64
		require.NoError(t, stack.DB.Model(&model.RolePermission{}).Where("role_id = ? AND permission_id = ?", role.ID, permission.ID).Count(&count).Error)
		assert.Equal(t, int64(1), count)
	})
}

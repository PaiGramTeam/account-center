//go:build integration

package integration

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/model"
)

func TestAdminRoleRoutesRegistered(t *testing.T) {
	stack := newIntegrationStack(t)

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/admin/roles"},
		{http.MethodPost, "/api/v1/admin/roles"},
		{http.MethodGet, "/api/v1/admin/roles/1"},
		{http.MethodPut, "/api/v1/admin/roles/1"},
		{http.MethodPatch, "/api/v1/admin/roles/1"},
		{http.MethodDelete, "/api/v1/admin/roles/1"},
		{http.MethodGet, "/api/v1/admin/roles/1/users"},
		{http.MethodPut, "/api/v1/admin/roles/1/users"},
		{http.MethodGet, "/api/v1/admin/roles/1/permissions"},
		{http.MethodPut, "/api/v1/admin/roles/1/permissions"},
	} {
		resp := performJSONRequest(t, stack.Router, tc.method, tc.path, nil, nil)
		assert.Equal(t, http.StatusUnauthorized, resp.Code, "%s %s should require auth", tc.method, tc.path)
	}

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/authorities"},
		{http.MethodPost, "/api/v1/authorities"},
		{http.MethodGet, "/api/v1/authorities/1"},
		{http.MethodPut, "/api/v1/authorities/1"},
		{http.MethodGet, "/api/v1/casbin/authorities/1/policies"},
		{http.MethodPut, "/api/v1/casbin/authorities/1/policies"},
	} {
		resp := performJSONRequest(t, stack.Router, tc.method, tc.path, nil, nil)
		assert.Equal(t, http.StatusNotFound, resp.Code, "%s %s should stay removed", tc.method, tc.path)
	}
}

func TestAdminRoleRoutesRespectPermissions(t *testing.T) {
	stack := newIntegrationStack(t)

	actorID, actorAccessToken, _, _, _ := registerVerifyAndLogin(t, stack, "role-route-actor")
	headers := authHeaders(actorAccessToken)

	role := model.Role{Name: "route-role", DisplayName: "Route Role", Description: "route role"}
	require.NoError(t, stack.DB.Create(&role).Error)

	listDenied := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/admin/roles", nil, headers)
	require.Equal(t, http.StatusForbidden, listDenied.Code, listDenied.Body.String())
	assert.Equal(t, "ADMIN_REQUIRED", decodeErrorCode(t, listDenied))

	grantPermissionsToUser(t, stack, actorID, model.BuildPermissionName(model.ResourceRole, model.ActionRead))
	listStillDenied := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/admin/roles", nil, headers)
	require.Equal(t, http.StatusForbidden, listStillDenied.Code, listStillDenied.Body.String())
	assert.Equal(t, "ADMIN_REQUIRED", decodeErrorCode(t, listStillDenied))

	grantAdminRoleToUser(t, stack, actorID)
	listAllowed := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/admin/roles", nil, headers)
	require.Equal(t, http.StatusOK, listAllowed.Code, listAllowed.Body.String())

	createAllowed := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/admin/roles", map[string]any{
		"name":         "new-role",
		"display_name": "New Role",
	}, headers)
	require.Equal(t, http.StatusOK, createAllowed.Code, createAllowed.Body.String())
}

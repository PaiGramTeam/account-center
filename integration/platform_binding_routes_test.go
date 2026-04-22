//go:build integration

package integration

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	platformv1 "github.com/PaiGramTeam/proto-contracts/platform/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"paigram/internal/model"
	"paigram/internal/response"
	serviceplatformbinding "paigram/internal/service/platformbinding"
)

func TestMePlatformAccountRoutesEnforceOwnership(t *testing.T) {
	stack := newIntegrationStack(t)

	ownerID, ownerAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-owner-%d@example.com", time.Now().UnixNano()), "OwnerPass123!")
	_, otherAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-other-%d@example.com", time.Now().UnixNano()), "OwnerPass123!")

	binding := model.PlatformAccountBinding{
		OwnerUserID:        ownerID,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:123", Valid: true},
		PlatformServiceKey: "platform-mihomo-service",
		DisplayName:        "CN Main",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, stack.DB.Create(&binding).Error)

	profile := model.PlatformAccountProfile{
		BindingID:          binding.ID,
		PlatformProfileKey: "mihomo:10001",
		GameBiz:            "hk4e_cn",
		Region:             "cn_gf01",
		PlayerUID:          "10001",
		Nickname:           "Traveler",
		IsPrimary:          true,
	}
	require.NoError(t, stack.DB.Create(&profile).Error)
	grant := model.ConsumerGrant{
		BindingID: binding.ID,
		Consumer:  serviceplatformbinding.ConsumerPaiGramBot,
		Status:    model.ConsumerGrantStatusActive,
		GrantedBy: sql.NullInt64{Int64: int64(ownerID), Valid: true},
		GrantedAt: time.Now().UTC(),
	}
	require.NoError(t, stack.DB.Create(&grant).Error)

	t.Run("owner can access self-service endpoints", func(t *testing.T) {
		for _, tc := range []struct {
			method string
			path   string
			body   any
		}{
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/me/platform-accounts/%d", binding.ID)},
			{method: http.MethodPatch, path: fmt.Sprintf("/api/v1/me/platform-accounts/%d", binding.ID), body: map[string]any{"display_name": "CN Main Updated"}},
			{method: http.MethodPatch, path: fmt.Sprintf("/api/v1/me/platform-accounts/%d/primary-profile", binding.ID), body: map[string]any{"profile_id": profile.ID}},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/me/platform-accounts/%d/profiles", binding.ID)},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/me/platform-accounts/%d/consumer-grants", binding.ID)},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/me/platform-accounts/%d/summary", binding.ID)},
			{method: http.MethodPut, path: fmt.Sprintf("/api/v1/me/platform-accounts/%d/consumer-grants/%s", binding.ID, serviceplatformbinding.ConsumerPaiGramBot), body: map[string]any{"enabled": true}},
		} {
			resp := performJSONRequest(t, stack.Router, tc.method, tc.path, tc.body, authHeaders(ownerAccessToken))
			require.NotEqual(t, http.StatusNotFound, resp.Code, "%s %s should be owner-accessible: %s", tc.method, tc.path, resp.Body.String())
		}
	})

	t.Run("other users get 404 for owner-scoped endpoints", func(t *testing.T) {
		for _, tc := range []struct {
			method string
			path   string
			body   any
		}{
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/me/platform-accounts/%d", binding.ID)},
			{method: http.MethodPatch, path: fmt.Sprintf("/api/v1/me/platform-accounts/%d", binding.ID), body: map[string]any{"display_name": "Denied"}},
			{method: http.MethodPatch, path: fmt.Sprintf("/api/v1/me/platform-accounts/%d/primary-profile", binding.ID), body: map[string]any{"profile_id": profile.ID}},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/me/platform-accounts/%d/profiles", binding.ID)},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/me/platform-accounts/%d/consumer-grants", binding.ID)},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/me/platform-accounts/%d/summary", binding.ID)},
			{method: http.MethodPut, path: fmt.Sprintf("/api/v1/me/platform-accounts/%d/consumer-grants/%s", binding.ID, serviceplatformbinding.ConsumerPaiGramBot), body: map[string]any{"enabled": false}},
			{method: http.MethodDelete, path: fmt.Sprintf("/api/v1/me/platform-accounts/%d", binding.ID)},
		} {
			resp := performJSONRequest(t, stack.Router, tc.method, tc.path, tc.body, authHeaders(otherAccessToken))
			require.Equal(t, http.StatusNotFound, resp.Code, "%s %s should be hidden from non-owners: %s", tc.method, tc.path, resp.Body.String())
			assert.Equal(t, "PLATFORM_BINDING_NOT_FOUND", decodeErrorCode(t, resp))
		}
	})
}

func TestPlatformBindingRoutes(t *testing.T) {
	stack := newIntegrationStack(t)

	ownerID, ownerAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-routes-owner-%d@example.com", time.Now().UnixNano()), "OwnerPass123!")
	adminID, adminAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-routes-admin-%d@example.com", time.Now().UnixNano()), "AdminPass123!")
	viewerID, viewerAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-routes-viewer-%d@example.com", time.Now().UnixNano()), "ViewerPass123!")
	grantAdminRoleToUser(t, stack, adminID)

	binding := model.PlatformAccountBinding{
		OwnerUserID:        ownerID,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:owner-main", Valid: true},
		PlatformServiceKey: "platform-mihomo-service",
		DisplayName:        "Owner Main",
		Status:             model.PlatformAccountBindingStatusActive,
		LastSyncedAt:       sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	require.NoError(t, stack.DB.Create(&binding).Error)

	profiles := []model.PlatformAccountProfile{
		{
			BindingID:          binding.ID,
			PlatformProfileKey: "mihomo:10001",
			GameBiz:            "hk4e_cn",
			Region:             "cn_gf01",
			PlayerUID:          "10001",
			Nickname:           "Traveler",
			Level:              sql.NullInt64{Int64: 60, Valid: true},
			IsPrimary:          true,
		},
		{
			BindingID:          binding.ID,
			PlatformProfileKey: "mihomo:10002",
			GameBiz:            "hk4e_global",
			Region:             "os_asia",
			PlayerUID:          "10002",
			Nickname:           "Lumine",
			Level:              sql.NullInt64{Int64: 58, Valid: true},
		},
	}
	require.NoError(t, stack.DB.Create(&profiles).Error)
	binding.PrimaryProfileID = sql.NullInt64{Int64: int64(profiles[0].ID), Valid: true}
	require.NoError(t, stack.DB.Model(&binding).Update("primary_profile_id", binding.PrimaryProfileID).Error)

	grant := model.ConsumerGrant{
		BindingID: binding.ID,
		Consumer:  serviceplatformbinding.ConsumerPaiGramBot,
		Status:    model.ConsumerGrantStatusActive,
		GrantedBy: sql.NullInt64{Int64: int64(ownerID), Valid: true},
		GrantedAt: time.Now().UTC(),
	}
	require.NoError(t, stack.DB.Create(&grant).Error)

	createStub := &platformBindingRouteStub{
		putResponse: &platformv1.PutCredentialResponse{Summary: &platformv1.GetCredentialSummaryResponse{
			PlatformAccountId: "cn:new-account",
			Status:            platformv1.CredentialStatus_CREDENTIAL_STATUS_ACTIVE,
		}},
	}
	seedEnabledPlatformService(t, stack, startPlatformBindingRouteServer(t, createStub))

	t.Run("me routes support list create get profiles grants put grant and delete", func(t *testing.T) {
		listResp := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me/platform-accounts", nil, authHeaders(ownerAccessToken))
		require.Equal(t, http.StatusOK, listResp.Code, listResp.Body.String())
		listData := decodeResponseData(t, listResp)
		items, ok := listData["items"].([]any)
		require.True(t, ok, "expected items array, got %T", listData["items"])
		assert.Len(t, items, 1)

		createResp := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/me/platform-accounts", map[string]any{
			"platform":           "mihomo",
			"display_name":       "New Draft",
			"credential_payload": map[string]any{"cookie_bundle": "abc"},
		}, authHeaders(ownerAccessToken))
		require.Equal(t, http.StatusCreated, createResp.Code, createResp.Body.String())
		createdData := decodeResponseData(t, createResp)
		createdID, ok := createdData["id"].(float64)
		require.True(t, ok, "expected numeric id, got %T", createdData["id"])
		assert.Equal(t, string(model.PlatformAccountBindingStatusActive), createdData["status"])
		assert.Equal(t, "cn:new-account", createdData["external_account_key"])

		getResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/me/platform-accounts/%d", binding.ID), nil, authHeaders(ownerAccessToken))
		require.Equal(t, http.StatusOK, getResp.Code, getResp.Body.String())
		getData := decodeResponseData(t, getResp)
		assert.Equal(t, binding.DisplayName, getData["display_name"])

		patchResp := performJSONRequest(t, stack.Router, http.MethodPatch, fmt.Sprintf("/api/v1/me/platform-accounts/%d", binding.ID), map[string]any{
			"display_name":         "Owner Main Updated",
			"platform_service_key": "platform-mihomo-service-v2",
		}, authHeaders(ownerAccessToken))
		require.Equal(t, http.StatusOK, patchResp.Code, patchResp.Body.String())
		patchData := decodeResponseData(t, patchResp)
		assert.Equal(t, "Owner Main Updated", patchData["display_name"])
		assert.Equal(t, "platform-mihomo-service-v2", patchData["platform_service_key"])

		profilesResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/me/platform-accounts/%d/profiles", binding.ID), nil, authHeaders(ownerAccessToken))
		require.Equal(t, http.StatusOK, profilesResp.Code, profilesResp.Body.String())
		profilesData := decodeResponseData(t, profilesResp)
		profileItems, ok := profilesData["items"].([]any)
		require.True(t, ok, "expected profile items array, got %T", profilesData["items"])
		assert.Len(t, profileItems, 2)

		patchPrimaryResp := performJSONRequest(t, stack.Router, http.MethodPatch, fmt.Sprintf("/api/v1/me/platform-accounts/%d/primary-profile", binding.ID), map[string]any{
			"profile_id": profiles[1].ID,
		}, authHeaders(ownerAccessToken))
		require.Equal(t, http.StatusOK, patchPrimaryResp.Code, patchPrimaryResp.Body.String())
		patchPrimaryData := decodeResponseData(t, patchPrimaryResp)
		assert.Equal(t, float64(profiles[1].ID), patchPrimaryData["primary_profile_id"])

		invalidPrimaryResp := performJSONRequest(t, stack.Router, http.MethodPatch, fmt.Sprintf("/api/v1/me/platform-accounts/%d/primary-profile", binding.ID), map[string]any{
			"profile_id": uint64(99999999),
		}, authHeaders(ownerAccessToken))
		require.Equal(t, http.StatusUnprocessableEntity, invalidPrimaryResp.Code, invalidPrimaryResp.Body.String())
		assert.Equal(t, "PRIMARY_PROFILE_INVALID", decodeErrorCode(t, invalidPrimaryResp))

		summaryResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/me/platform-accounts/%d/summary", binding.ID), nil, authHeaders(ownerAccessToken))
		require.Equal(t, http.StatusOK, summaryResp.Code, summaryResp.Body.String())
		summaryData := decodeResponseData(t, summaryResp)
		assert.Equal(t, "Owner Main Updated", summaryData["display_name"])
		assert.Equal(t, float64(profiles[1].ID), summaryData["primary_profile_id"])
		summaryProfiles, ok := summaryData["profiles"].([]any)
		require.True(t, ok, "expected summary profiles array, got %T", summaryData["profiles"])
		assert.Len(t, summaryProfiles, 2)

		grantsResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/me/platform-accounts/%d/consumer-grants", binding.ID), nil, authHeaders(ownerAccessToken))
		require.Equal(t, http.StatusOK, grantsResp.Code, grantsResp.Body.String())
		grantsData := decodeResponseData(t, grantsResp)
		grantItems, ok := grantsData["items"].([]any)
		require.True(t, ok, "expected grant items array, got %T", grantsData["items"])
		assert.Len(t, grantItems, 1)

		putGrantResp := performJSONRequest(t, stack.Router, http.MethodPut,
			fmt.Sprintf("/api/v1/me/platform-accounts/%d/consumer-grants/%s", binding.ID, serviceplatformbinding.ConsumerPaiGramBot),
			map[string]any{"enabled": false}, authHeaders(ownerAccessToken))
		require.Equal(t, http.StatusOK, putGrantResp.Code, putGrantResp.Body.String())
		putGrantData := decodeResponseData(t, putGrantResp)
		assert.Equal(t, string(model.ConsumerGrantStatusRevoked), putGrantData["status"])

		var revokedGrant model.ConsumerGrant
		require.NoError(t, stack.DB.Where("binding_id = ? AND consumer = ?", binding.ID, serviceplatformbinding.ConsumerPaiGramBot).First(&revokedGrant).Error)
		assert.Equal(t, model.ConsumerGrantStatusRevoked, revokedGrant.Status)
		assert.True(t, revokedGrant.RevokedAt.Valid)

		deleteResp := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/me/platform-accounts/%d", uint64(createdID)), nil, authHeaders(ownerAccessToken))
		require.Equal(t, http.StatusNoContent, deleteResp.Code, deleteResp.Body.String())
	})

	t.Run("admin routes require admin authorization", func(t *testing.T) {
		for _, tc := range []struct {
			method string
			path   string
			body   any
		}{
			{method: http.MethodGet, path: "/api/v1/admin/platform-accounts"},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/admin/platform-accounts/%d", binding.ID)},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/admin/platform-accounts/%d/profiles", binding.ID)},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/admin/platform-accounts/%d/consumer-grants", binding.ID)},
			{method: http.MethodPut, path: fmt.Sprintf("/api/v1/admin/platform-accounts/%d/consumer-grants/%s", binding.ID, serviceplatformbinding.ConsumerPaiGramBot), body: map[string]any{"enabled": true}},
			{method: http.MethodPost, path: fmt.Sprintf("/api/v1/admin/platform-accounts/%d/refresh", binding.ID)},
		} {
			resp := performJSONRequest(t, stack.Router, tc.method, tc.path, tc.body, authHeaders(viewerAccessToken))
			require.Equal(t, http.StatusForbidden, resp.Code, "%s %s should require admin: %s", tc.method, tc.path, resp.Body.String())
			assert.Equal(t, "ADMIN_REQUIRED", decodeErrorCode(t, resp))
		}

		grantPermissionsToUser(t, stack, viewerID,
			model.BuildPermissionName(model.ResourcePlatformAccount, model.ActionList),
			model.BuildPermissionName(model.ResourcePlatformAccount, model.ActionRead),
			model.BuildPermissionName(model.ResourcePlatformAccount, model.ActionUpdate),
			model.BuildPermissionName(model.ResourcePlatformAccount, model.ActionDelete),
		)

		for _, tc := range []struct {
			method string
			path   string
			body   any
		}{
			{method: http.MethodGet, path: "/api/v1/admin/platform-accounts"},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/admin/platform-accounts/%d", binding.ID)},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/admin/platform-accounts/%d/profiles", binding.ID)},
			{method: http.MethodGet, path: fmt.Sprintf("/api/v1/admin/platform-accounts/%d/consumer-grants", binding.ID)},
			{method: http.MethodPut, path: fmt.Sprintf("/api/v1/admin/platform-accounts/%d/consumer-grants/%s", binding.ID, serviceplatformbinding.ConsumerPaiGramBot), body: map[string]any{"enabled": true}},
			{method: http.MethodPost, path: fmt.Sprintf("/api/v1/admin/platform-accounts/%d/refresh", binding.ID)},
		} {
			resp := performJSONRequest(t, stack.Router, tc.method, tc.path, tc.body, authHeaders(viewerAccessToken))
			require.Equal(t, http.StatusForbidden, resp.Code, "%s %s should reject non-admins even with permissions: %s", tc.method, tc.path, resp.Body.String())
			assert.Equal(t, "ADMIN_REQUIRED", decodeErrorCode(t, resp))
		}

		listResp := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/admin/platform-accounts", nil, authHeaders(adminAccessToken))
		require.Equal(t, http.StatusOK, listResp.Code, listResp.Body.String())

		getResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/platform-accounts/%d", binding.ID), nil, authHeaders(adminAccessToken))
		require.Equal(t, http.StatusOK, getResp.Code, getResp.Body.String())

		profilesResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/platform-accounts/%d/profiles", binding.ID), nil, authHeaders(adminAccessToken))
		require.Equal(t, http.StatusOK, profilesResp.Code, profilesResp.Body.String())

		grantsResp := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/admin/platform-accounts/%d/consumer-grants", binding.ID), nil, authHeaders(adminAccessToken))
		require.Equal(t, http.StatusOK, grantsResp.Code, grantsResp.Body.String())

		putGrantResp := performJSONRequest(t, stack.Router, http.MethodPut,
			fmt.Sprintf("/api/v1/admin/platform-accounts/%d/consumer-grants/%s", binding.ID, serviceplatformbinding.ConsumerPaiGramBot),
			map[string]any{"enabled": true}, authHeaders(adminAccessToken))
		require.Equal(t, http.StatusOK, putGrantResp.Code, putGrantResp.Body.String())

		refreshResp := performJSONRequest(t, stack.Router, http.MethodPost, fmt.Sprintf("/api/v1/admin/platform-accounts/%d/refresh", binding.ID), nil, authHeaders(adminAccessToken))
		require.Contains(t, []int{http.StatusOK, http.StatusServiceUnavailable}, refreshResp.Code, refreshResp.Body.String())
		if refreshResp.Code == http.StatusOK {
			refreshData := decodeResponseData(t, refreshResp)
			assert.Equal(t, string(model.PlatformAccountBindingStatusRefreshRequired), refreshData["status"])
		}

		deletable := model.PlatformAccountBinding{
			OwnerUserID:        ownerID,
			Platform:           "mihomo",
			ExternalAccountKey: sql.NullString{String: fmt.Sprintf("cn:delete-%d", time.Now().UnixNano()), Valid: true},
			PlatformServiceKey: "platform-mihomo-service",
			DisplayName:        "Delete Me",
			Status:             model.PlatformAccountBindingStatusActive,
		}
		require.NoError(t, stack.DB.Create(&deletable).Error)

		deleteUnauthorizedResp := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/admin/platform-accounts/%d", deletable.ID), nil, authHeaders(viewerAccessToken))
		require.Equal(t, http.StatusForbidden, deleteUnauthorizedResp.Code, deleteUnauthorizedResp.Body.String())
		assert.Equal(t, "ADMIN_REQUIRED", decodeErrorCode(t, deleteUnauthorizedResp))

		deleteResp := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/admin/platform-accounts/%d", deletable.ID), nil, authHeaders(adminAccessToken))
		require.Equal(t, http.StatusNoContent, deleteResp.Code, deleteResp.Body.String())
	})

	_ = viewerID
}

func TestPlatformBindingConsumerGrantRoutesSupportRegistryConsumersAndIdempotentDisable(t *testing.T) {
	stack := newIntegrationStack(t)

	ownerID, ownerAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-consumer-owner-%d@example.com", time.Now().UnixNano()), "OwnerPass123!")
	adminID, adminAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-consumer-admin-%d@example.com", time.Now().UnixNano()), "AdminPass123!")
	grantAdminRoleToUser(t, stack, adminID)

	binding := model.PlatformAccountBinding{
		OwnerUserID:        ownerID,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: fmt.Sprintf("cn:consumer-%d", time.Now().UnixNano()), Valid: true},
		PlatformServiceKey: "platform-mihomo-service",
		DisplayName:        "Consumer Binding",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, stack.DB.Create(&binding).Error)

	enableResp := performJSONRequest(t, stack.Router, http.MethodPut,
		fmt.Sprintf("/api/v1/me/platform-accounts/%d/consumer-grants/%s", binding.ID, serviceplatformbinding.ConsumerPaiGramBot),
		map[string]any{"enabled": true}, authHeaders(ownerAccessToken))
	require.Equal(t, http.StatusOK, enableResp.Code, enableResp.Body.String())
	assert.Equal(t, string(model.ConsumerGrantStatusActive), decodeResponseData(t, enableResp)["status"])

	disableResp := performJSONRequest(t, stack.Router, http.MethodPut,
		fmt.Sprintf("/api/v1/me/platform-accounts/%d/consumer-grants/%s", binding.ID, serviceplatformbinding.ConsumerPaiGramBot),
		map[string]any{"enabled": false}, authHeaders(ownerAccessToken))
	require.Equal(t, http.StatusOK, disableResp.Code, disableResp.Body.String())
	assert.Equal(t, string(model.ConsumerGrantStatusRevoked), decodeResponseData(t, disableResp)["status"])

	repeatDisableResp := performJSONRequest(t, stack.Router, http.MethodPut,
		fmt.Sprintf("/api/v1/me/platform-accounts/%d/consumer-grants/%s", binding.ID, serviceplatformbinding.ConsumerPaiGramBot),
		map[string]any{"enabled": false}, authHeaders(ownerAccessToken))
	require.Equal(t, http.StatusOK, repeatDisableResp.Code, repeatDisableResp.Body.String())
	assert.Equal(t, string(model.ConsumerGrantStatusRevoked), decodeResponseData(t, repeatDisableResp)["status"])

	pamgramResp := performJSONRequest(t, stack.Router, http.MethodPut,
		fmt.Sprintf("/api/v1/admin/platform-accounts/%d/consumer-grants/%s", binding.ID, serviceplatformbinding.ConsumerPamgram),
		map[string]any{"enabled": true}, authHeaders(adminAccessToken))
	require.Equal(t, http.StatusOK, pamgramResp.Code, pamgramResp.Body.String())
	pamgramData := decodeResponseData(t, pamgramResp)
	assert.Equal(t, serviceplatformbinding.ConsumerPamgram, pamgramData["consumer"])
	assert.Equal(t, string(model.ConsumerGrantStatusActive), pamgramData["status"])

	unsupportedResp := performJSONRequest(t, stack.Router, http.MethodPut,
		fmt.Sprintf("/api/v1/me/platform-accounts/%d/consumer-grants/%s", binding.ID, "unsupported-consumer"),
		map[string]any{"enabled": true}, authHeaders(ownerAccessToken))
	require.Equal(t, http.StatusBadRequest, unsupportedResp.Code, unsupportedResp.Body.String())
	assert.Equal(t, response.ErrCodeInvalidInput, decodeErrorCode(t, unsupportedResp))

	var grants []model.ConsumerGrant
	require.NoError(t, stack.DB.Where("binding_id = ?", binding.ID).Order("consumer ASC").Find(&grants).Error)
	require.Len(t, grants, 2)
	assert.Equal(t, serviceplatformbinding.ConsumerPaiGramBot, grants[0].Consumer)
	assert.Equal(t, model.ConsumerGrantStatusRevoked, grants[0].Status)
	assert.Equal(t, serviceplatformbinding.ConsumerPamgram, grants[1].Consumer)
	assert.Equal(t, model.ConsumerGrantStatusActive, grants[1].Status)
}

func TestPlatformBindingConsumerGrantDisableIsIdempotentWhenGrantIsMissing(t *testing.T) {
	stack := newIntegrationStack(t)

	ownerID, ownerAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-grant-missing-owner-%d@example.com", time.Now().UnixNano()), "OwnerPass123!")
	adminID, adminAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-grant-missing-admin-%d@example.com", time.Now().UnixNano()), "AdminPass123!")
	grantAdminRoleToUser(t, stack, adminID)

	binding := model.PlatformAccountBinding{
		OwnerUserID:        ownerID,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: fmt.Sprintf("cn:grant-missing-%d", time.Now().UnixNano()), Valid: true},
		PlatformServiceKey: "platform-mihomo-service",
		DisplayName:        "Grant Missing",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, stack.DB.Create(&binding).Error)

	for _, tc := range []struct {
		name    string
		path    string
		headers map[string]string
	}{
		{name: "owner", path: fmt.Sprintf("/api/v1/me/platform-accounts/%d/consumer-grants/%s", binding.ID, serviceplatformbinding.ConsumerPaiGramBot), headers: authHeaders(ownerAccessToken)},
		{name: "admin", path: fmt.Sprintf("/api/v1/admin/platform-accounts/%d/consumer-grants/%s", binding.ID, serviceplatformbinding.ConsumerPaiGramBot), headers: authHeaders(adminAccessToken)},
	} {
		resp := performJSONRequest(t, stack.Router, http.MethodPut, tc.path, map[string]any{"enabled": false}, tc.headers)
		require.Equal(t, http.StatusOK, resp.Code, "%s => %s", tc.name, resp.Body.String())
		data := decodeResponseData(t, resp)
		assert.Equal(t, float64(binding.ID), data["binding_id"])
		assert.Equal(t, serviceplatformbinding.ConsumerPaiGramBot, data["consumer"])
		assert.Equal(t, string(model.ConsumerGrantStatusRevoked), data["status"])
	}
}

func TestCreatePlatformBindingRouteBindsImmediately(t *testing.T) {
	stack := newIntegrationStack(t)
	ownerID, ownerAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-create-%d@example.com", time.Now().UnixNano()), "OwnerPass123!")

	stub := &platformBindingRouteStub{
		putResponse: &platformv1.PutCredentialResponse{Summary: &platformv1.GetCredentialSummaryResponse{
			PlatformAccountId: "cn:route-success",
			Status:            platformv1.CredentialStatus_CREDENTIAL_STATUS_ACTIVE,
			LastValidatedAt:   timestamppb.New(time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)),
			LastRefreshedAt:   timestamppb.New(time.Date(2026, 4, 20, 12, 5, 0, 0, time.UTC)),
			Profiles: []*platformv1.ProfileSummary{{
				Id:                42,
				PlatformAccountId: "cn:route-success",
				GameBiz:           "hk4e_cn",
				Region:            "cn_gf01",
				PlayerId:          "10001",
				Nickname:          "Traveler",
				Level:             60,
				IsDefault:         true,
			}},
		}},
	}
	endpoint := startPlatformBindingRouteServer(t, stub)
	seedEnabledPlatformService(t, stack, endpoint)

	resp := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/me/platform-accounts", map[string]any{
		"platform":           "mihomo",
		"display_name":       "Main Mihomo Account",
		"credential_payload": map[string]any{"cookie_bundle": "abc"},
	}, authHeaders(ownerAccessToken))
	require.Equal(t, http.StatusCreated, resp.Code, resp.Body.String())
	data := decodeResponseData(t, resp)
	assert.Equal(t, "active", data["status"])
	assert.Equal(t, "cn:route-success", data["external_account_key"])
	assert.Equal(t, "platform-mihomo-service", data["platform_service_key"])

	var binding model.PlatformAccountBinding
	require.NoError(t, stack.DB.Where("owner_user_id = ? AND platform = ?", ownerID, "mihomo").First(&binding).Error)
	assert.Equal(t, model.PlatformAccountBindingStatusActive, binding.Status)
	assert.Equal(t, "cn:route-success", binding.ExternalAccountKey.String)

	var profiles []model.PlatformAccountProfile
	require.NoError(t, stack.DB.Where("binding_id = ?", binding.ID).Order("id ASC").Find(&profiles).Error)
	require.Len(t, profiles, 1)
	assert.Equal(t, "Traveler", profiles[0].Nickname)
	assert.True(t, profiles[0].IsPrimary)
	assert.Equal(t, int64(profiles[0].ID), binding.PrimaryProfileID.Int64)
	assert.Empty(t, stub.lastPut.GetPlatformAccountId())
	assert.JSONEq(t, `{"cookie_bundle":"abc"}`, stub.lastPut.GetCredentialPayloadJson())
	assert.Empty(t, stub.deleteRequests)
	assert.Empty(t, data["status_reason_code"])
	assert.Empty(t, data["status_reason_message"])
	_ = ownerID
}

func TestCreatePlatformBindingRouteHandlesDuplicateOwnerConflict(t *testing.T) {
	stack := newIntegrationStack(t)
	ownerID, ownerAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-conflict-%d@example.com", time.Now().UnixNano()), "OwnerPass123!")
	otherOwner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, stack.DB.Create(&otherOwner).Error)
	require.NoError(t, stack.DB.Create(&model.PlatformAccountBinding{
		OwnerUserID:        otherOwner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:duplicate-owner", Valid: true},
		PlatformServiceKey: "platform-mihomo-service",
		DisplayName:        "Existing Owner",
		Status:             model.PlatformAccountBindingStatusActive,
	}).Error)

	stub := &platformBindingRouteStub{
		putResponse: &platformv1.PutCredentialResponse{Summary: &platformv1.GetCredentialSummaryResponse{
			PlatformAccountId: "cn:duplicate-owner",
			Status:            platformv1.CredentialStatus_CREDENTIAL_STATUS_ACTIVE,
		}},
	}
	endpoint := startPlatformBindingRouteServer(t, stub)
	seedEnabledPlatformService(t, stack, endpoint)

	resp := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/me/platform-accounts", map[string]any{
		"platform":           "mihomo",
		"display_name":       "Conflict Draft",
		"credential_payload": map[string]any{"cookie_bundle": "abc"},
	}, authHeaders(ownerAccessToken))
	require.Equal(t, http.StatusConflict, resp.Code, resp.Body.String())
	assert.Equal(t, "PLATFORM_ACCOUNT_ALREADY_BOUND", decodeErrorCode(t, resp))

	var binding model.PlatformAccountBinding
	require.NoError(t, stack.DB.Where("owner_user_id = ? AND display_name = ?", ownerID, "Conflict Draft").First(&binding).Error)
	assert.Equal(t, model.PlatformAccountBindingStatusCredentialInvalid, binding.Status)
	assert.Equal(t, "duplicate_owner", binding.StatusReasonCode)
	assert.False(t, binding.ExternalAccountKey.Valid)
	require.Len(t, stub.deleteRequests, 1)
	assert.Equal(t, "cn:duplicate-owner", stub.deleteRequests[0].GetPlatformAccountId())
	_ = ownerID
}

func TestCreatePlatformBindingRouteMarksDraftInvalidOnProviderValidationFailure(t *testing.T) {
	stack := newIntegrationStack(t)
	ownerID, ownerAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-invalid-%d@example.com", time.Now().UnixNano()), "OwnerPass123!")

	stub := &platformBindingRouteStub{putErr: grpcstatus.Error(codes.InvalidArgument, "credential rejected")}
	endpoint := startPlatformBindingRouteServer(t, stub)
	seedEnabledPlatformService(t, stack, endpoint)

	resp := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/me/platform-accounts", map[string]any{
		"platform":           "mihomo",
		"display_name":       "Invalid Draft",
		"credential_payload": map[string]any{"cookie_bundle": "bad"},
	}, authHeaders(ownerAccessToken))
	require.Equal(t, http.StatusUnprocessableEntity, resp.Code, resp.Body.String())

	var binding model.PlatformAccountBinding
	require.NoError(t, stack.DB.Where("owner_user_id = ? AND display_name = ?", ownerID, "Invalid Draft").First(&binding).Error)
	assert.Equal(t, model.PlatformAccountBindingStatusCredentialInvalid, binding.Status)
	assert.Equal(t, "credential_validation_failed", binding.StatusReasonCode)
	assert.False(t, binding.ExternalAccountKey.Valid)
	assert.Empty(t, stub.deleteRequests)
	_ = ownerID
}

func TestCreatePlatformBindingRouteMarksDeleteFailedWhenCleanupFails(t *testing.T) {
	stack := newIntegrationStack(t)
	ownerID, ownerAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-delete-failed-%d@example.com", time.Now().UnixNano()), "OwnerPass123!")
	otherOwner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, stack.DB.Create(&otherOwner).Error)
	require.NoError(t, stack.DB.Create(&model.PlatformAccountBinding{
		OwnerUserID:        otherOwner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:cleanup-failed", Valid: true},
		PlatformServiceKey: "platform-mihomo-service",
		DisplayName:        "Existing Owner",
		Status:             model.PlatformAccountBindingStatusActive,
	}).Error)

	stub := &platformBindingRouteStub{
		putResponse: &platformv1.PutCredentialResponse{Summary: &platformv1.GetCredentialSummaryResponse{
			PlatformAccountId: "cn:cleanup-failed",
			Status:            platformv1.CredentialStatus_CREDENTIAL_STATUS_ACTIVE,
		}},
		deleteErr: grpcstatus.Error(codes.Unavailable, "cleanup down"),
	}
	endpoint := startPlatformBindingRouteServer(t, stub)
	seedEnabledPlatformService(t, stack, endpoint)

	resp := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/me/platform-accounts", map[string]any{
		"platform":           "mihomo",
		"display_name":       "Cleanup Failed Draft",
		"credential_payload": map[string]any{"cookie_bundle": "abc"},
	}, authHeaders(ownerAccessToken))
	require.Equal(t, http.StatusConflict, resp.Code, resp.Body.String())

	var binding model.PlatformAccountBinding
	require.NoError(t, stack.DB.Where("owner_user_id = ? AND display_name = ?", ownerID, "Cleanup Failed Draft").First(&binding).Error)
	assert.Equal(t, model.PlatformAccountBindingStatusDeleteFailed, binding.Status)
	assert.Equal(t, "compensation_delete_failed", binding.StatusReasonCode)
	assert.False(t, binding.ExternalAccountKey.Valid)
	require.Len(t, stub.deleteRequests, 1)
	_ = ownerID
}

func TestCreatePlatformBindingRouteReturnsExistingBindingForSameOwnerRetry(t *testing.T) {
	stack := newIntegrationStack(t)
	ownerID, ownerAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-same-owner-%d@example.com", time.Now().UnixNano()), "OwnerPass123!")
	existing := model.PlatformAccountBinding{
		OwnerUserID:        ownerID,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:same-owner", Valid: true},
		PlatformServiceKey: "platform-mihomo-service",
		DisplayName:        "Existing Binding",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, stack.DB.Create(&existing).Error)

	stub := &platformBindingRouteStub{
		putResponse: &platformv1.PutCredentialResponse{Summary: &platformv1.GetCredentialSummaryResponse{
			PlatformAccountId: "cn:same-owner",
			Status:            platformv1.CredentialStatus_CREDENTIAL_STATUS_ACTIVE,
		}},
	}
	endpoint := startPlatformBindingRouteServer(t, stub)
	seedEnabledPlatformService(t, stack, endpoint)

	resp := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/me/platform-accounts", map[string]any{
		"platform":           "mihomo",
		"display_name":       "Retry Draft",
		"credential_payload": map[string]any{"cookie_bundle": "abc"},
	}, authHeaders(ownerAccessToken))
	require.Equal(t, http.StatusCreated, resp.Code, resp.Body.String())
	data := decodeResponseData(t, resp)
	assert.Equal(t, float64(existing.ID), data["id"])
	assert.Equal(t, "cn:same-owner", data["external_account_key"])
	assert.Empty(t, stub.deleteRequests)

	var drafts []model.PlatformAccountBinding
	require.NoError(t, stack.DB.Where("owner_user_id = ? AND display_name = ?", ownerID, "Retry Draft").Find(&drafts).Error)
	assert.Len(t, drafts, 0)
}

func TestPlatformBindingCredentialUpdateRoutesRemainSupported(t *testing.T) {
	stack := newIntegrationStack(t)
	ownerID, ownerAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-put-owner-%d@example.com", time.Now().UnixNano()), "OwnerPass123!")
	adminID, adminAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-put-admin-%d@example.com", time.Now().UnixNano()), "AdminPass123!")
	grantAdminRoleToUser(t, stack, adminID)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        ownerID,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:update-path", Valid: true},
		PlatformServiceKey: "platform-mihomo-service",
		DisplayName:        "Update Path",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, stack.DB.Create(&binding).Error)

	stub := &platformBindingRouteStub{
		putResponse: &platformv1.PutCredentialResponse{Summary: &platformv1.GetCredentialSummaryResponse{
			PlatformAccountId: "cn:update-path",
			Status:            platformv1.CredentialStatus_CREDENTIAL_STATUS_ACTIVE,
		}},
	}
	endpoint := startPlatformBindingRouteServer(t, stub)
	seedEnabledPlatformService(t, stack, endpoint)

	meResp := performJSONRequest(t, stack.Router, http.MethodPut, fmt.Sprintf("/api/v1/me/platform-accounts/%d/credential", binding.ID), map[string]any{
		"cookie_bundle": "owner-update",
	}, authHeaders(ownerAccessToken))
	require.Equal(t, http.StatusOK, meResp.Code, meResp.Body.String())
	meData := decodeResponseData(t, meResp)
	assert.Equal(t, "cn:update-path", meData["platform_account_id"])
	assert.Equal(t, "cn:update-path", stub.lastPut.GetPlatformAccountId())
	assert.JSONEq(t, `{"cookie_bundle":"owner-update"}`, stub.lastPut.GetCredentialPayloadJson())

	adminResp := performJSONRequest(t, stack.Router, http.MethodPut, fmt.Sprintf("/api/v1/admin/platform-accounts/%d/credential", binding.ID), map[string]any{
		"cookie_bundle": "admin-update",
	}, authHeaders(adminAccessToken))
	require.Equal(t, http.StatusOK, adminResp.Code, adminResp.Body.String())
	adminData := decodeResponseData(t, adminResp)
	assert.Equal(t, "cn:update-path", adminData["platform_account_id"])
	assert.Equal(t, "cn:update-path", stub.lastPut.GetPlatformAccountId())
	assert.JSONEq(t, `{"cookie_bundle":"admin-update"}`, stub.lastPut.GetCredentialPayloadJson())
}

func TestMeDeletePlatformBindingRouteDeletesProviderCredentialAndControlPlaneState(t *testing.T) {
	stack := newIntegrationStack(t)
	ownerID, ownerAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-delete-owner-%d@example.com", time.Now().UnixNano()), "OwnerPass123!")
	binding := model.PlatformAccountBinding{
		OwnerUserID:        ownerID,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:delete-owner", Valid: true},
		PlatformServiceKey: "platform-mihomo-service",
		DisplayName:        "Delete Owner",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, stack.DB.Create(&binding).Error)
	require.NoError(t, stack.DB.Create(&model.PlatformAccountProfile{
		BindingID:          binding.ID,
		PlatformProfileKey: "mihomo:delete-owner",
		GameBiz:            "hk4e_cn",
		Region:             "cn_gf01",
		PlayerUID:          "10001",
		Nickname:           "Traveler",
		IsPrimary:          true,
	}).Error)
	require.NoError(t, stack.DB.Create(&model.ConsumerGrant{
		BindingID: binding.ID,
		Consumer:  serviceplatformbinding.ConsumerPaiGramBot,
		Status:    model.ConsumerGrantStatusActive,
		GrantedBy: sql.NullInt64{Int64: int64(ownerID), Valid: true},
		GrantedAt: time.Now().UTC(),
	}).Error)
	stub := &platformBindingRouteStub{}
	seedEnabledPlatformService(t, stack, startPlatformBindingRouteServer(t, stub))

	resp := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/me/platform-accounts/%d", binding.ID), nil, authHeaders(ownerAccessToken))
	require.Equal(t, http.StatusNoContent, resp.Code, resp.Body.String())
	require.Len(t, stub.deleteRequests, 1)
	assert.Equal(t, "cn:delete-owner", stub.deleteRequests[0].GetPlatformAccountId())

	var bindingCount int64
	require.NoError(t, stack.DB.Model(&model.PlatformAccountBinding{}).Where("id = ?", binding.ID).Count(&bindingCount).Error)
	assert.Zero(t, bindingCount)
	var profileCount int64
	require.NoError(t, stack.DB.Model(&model.PlatformAccountProfile{}).Where("binding_id = ?", binding.ID).Count(&profileCount).Error)
	assert.Zero(t, profileCount)
	var grantCount int64
	require.NoError(t, stack.DB.Model(&model.ConsumerGrant{}).Where("binding_id = ?", binding.ID).Count(&grantCount).Error)
	assert.Zero(t, grantCount)
}

func TestAdminDeletePlatformBindingRouteDeletesProviderCredential(t *testing.T) {
	stack := newIntegrationStack(t)
	ownerID, _, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-delete-admin-owner-%d@example.com", time.Now().UnixNano()), "OwnerPass123!")
	adminID, adminAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-delete-admin-%d@example.com", time.Now().UnixNano()), "AdminPass123!")
	grantAdminRoleToUser(t, stack, adminID)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        ownerID,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:delete-admin", Valid: true},
		PlatformServiceKey: "platform-mihomo-service",
		DisplayName:        "Delete Admin",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, stack.DB.Create(&binding).Error)
	stub := &platformBindingRouteStub{}
	seedEnabledPlatformService(t, stack, startPlatformBindingRouteServer(t, stub))

	resp := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/admin/platform-accounts/%d", binding.ID), nil, authHeaders(adminAccessToken))
	require.Equal(t, http.StatusNoContent, resp.Code, resp.Body.String())
	require.Len(t, stub.deleteRequests, 1)
	assert.Equal(t, "cn:delete-admin", stub.deleteRequests[0].GetPlatformAccountId())
}

func TestDeletePlatformBindingRouteMarksDeleteFailedWhenProviderDeleteFails(t *testing.T) {
	stack := newIntegrationStack(t)
	ownerID, ownerAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-delete-failure-%d@example.com", time.Now().UnixNano()), "OwnerPass123!")
	binding := model.PlatformAccountBinding{
		OwnerUserID:        ownerID,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:delete-failure", Valid: true},
		PlatformServiceKey: "platform-mihomo-service",
		DisplayName:        "Delete Failure",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, stack.DB.Create(&binding).Error)
	stub := &platformBindingRouteStub{deleteErr: grpcstatus.Error(codes.Unavailable, "delete downstream unavailable")}
	seedEnabledPlatformService(t, stack, startPlatformBindingRouteServer(t, stub))

	resp := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/me/platform-accounts/%d", binding.ID), nil, authHeaders(ownerAccessToken))
	require.Equal(t, http.StatusServiceUnavailable, resp.Code, resp.Body.String())
	assert.Equal(t, "PLATFORM_SERVICE_UNAVAILABLE", decodeErrorCode(t, resp))

	var persisted model.PlatformAccountBinding
	require.NoError(t, stack.DB.First(&persisted, binding.ID).Error)
	assert.Equal(t, model.PlatformAccountBindingStatusDeleteFailed, persisted.Status)
	assert.Equal(t, "credential_delete_failed", persisted.StatusReasonCode)
	assert.Contains(t, persisted.StatusReasonMessage, "delete downstream unavailable")
	require.Len(t, stub.deleteRequests, 1)
}

func TestDeletePlatformBindingRouteReturnsNotFoundOnRepeatDelete(t *testing.T) {
	stack := newIntegrationStack(t)
	ownerID, ownerAccessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("binding-delete-repeat-%d@example.com", time.Now().UnixNano()), "OwnerPass123!")
	binding := model.PlatformAccountBinding{
		OwnerUserID:        ownerID,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:delete-repeat", Valid: true},
		PlatformServiceKey: "platform-mihomo-service",
		DisplayName:        "Delete Repeat",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, stack.DB.Create(&binding).Error)
	stub := &platformBindingRouteStub{}
	seedEnabledPlatformService(t, stack, startPlatformBindingRouteServer(t, stub))

	firstResp := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/me/platform-accounts/%d", binding.ID), nil, authHeaders(ownerAccessToken))
	require.Equal(t, http.StatusNoContent, firstResp.Code, firstResp.Body.String())
	secondResp := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/me/platform-accounts/%d", binding.ID), nil, authHeaders(ownerAccessToken))
	require.Equal(t, http.StatusNotFound, secondResp.Code, secondResp.Body.String())
	require.Len(t, stub.deleteRequests, 1)
}

type platformBindingRouteStub struct {
	platformv1.UnimplementedPlatformServiceServer
	putResponse              *platformv1.PutCredentialResponse
	putErr                   error
	deleteErr                error
	confirmPrimaryProfileErr error
	lastPut                  *platformv1.PutCredentialRequest
	deleteRequests           []*platformv1.DeleteCredentialRequest
}

func (s *platformBindingRouteStub) DescribePlatform(context.Context, *platformv1.DescribePlatformRequest) (*platformv1.DescribePlatformResponse, error) {
	return &platformv1.DescribePlatformResponse{}, nil
}

func (s *platformBindingRouteStub) GetCredentialSummary(context.Context, *platformv1.GetCredentialSummaryRequest) (*platformv1.GetCredentialSummaryResponse, error) {
	return &platformv1.GetCredentialSummaryResponse{}, nil
}

func (s *platformBindingRouteStub) PutCredential(_ context.Context, req *platformv1.PutCredentialRequest) (*platformv1.PutCredentialResponse, error) {
	s.lastPut = req
	if s.putErr != nil {
		return nil, s.putErr
	}
	return s.putResponse, nil
}

func (s *platformBindingRouteStub) RefreshCredential(context.Context, *platformv1.RefreshCredentialRequest) (*platformv1.RefreshCredentialResponse, error) {
	return &platformv1.RefreshCredentialResponse{}, nil
}

func (s *platformBindingRouteStub) DeleteCredential(_ context.Context, req *platformv1.DeleteCredentialRequest) (*platformv1.DeleteCredentialResponse, error) {
	s.deleteRequests = append(s.deleteRequests, req)
	if s.deleteErr != nil {
		return nil, s.deleteErr
	}
	return &platformv1.DeleteCredentialResponse{Success: true}, nil
}

func (s *platformBindingRouteStub) ConfirmPrimaryProfile(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	if s.confirmPrimaryProfileErr != nil {
		return nil, s.confirmPrimaryProfileErr
	}
	return &emptypb.Empty{}, nil
}

type confirmPrimaryProfileService interface {
	ConfirmPrimaryProfile(context.Context, *emptypb.Empty) (*emptypb.Empty, error)
}

var confirmPrimaryProfileServiceDesc = grpc.ServiceDesc{
	ServiceName: "mihomo.v1.MihomoAccountService",
	HandlerType: (*confirmPrimaryProfileService)(nil),
	Methods: []grpc.MethodDesc{{
		MethodName: "ConfirmPrimaryProfile",
		Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
			in := new(emptypb.Empty)
			if err := dec(in); err != nil {
				return nil, err
			}
			if interceptor == nil {
				return srv.(confirmPrimaryProfileService).ConfirmPrimaryProfile(ctx, in)
			}
			info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/mihomo.v1.MihomoAccountService/ConfirmPrimaryProfile"}
			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				return srv.(confirmPrimaryProfileService).ConfirmPrimaryProfile(ctx, req.(*emptypb.Empty))
			}
			return interceptor(ctx, in, info, handler)
		},
	}},
}

func startPlatformBindingRouteServer(t *testing.T, stub *platformBindingRouteStub) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	platformv1.RegisterPlatformServiceServer(server, stub)
	server.RegisterService(&confirmPrimaryProfileServiceDesc, stub)
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		<-serveErrCh
	})
	return listener.Addr().String()
}

func seedEnabledPlatformService(t *testing.T, stack *integrationStack, endpoint string) {
	t.Helper()
	require.NoError(t, stack.DB.Create(&model.PlatformService{
		PlatformKey:          "mihomo",
		DisplayName:          "Mihomo",
		ServiceKey:           "platform-mihomo-service",
		ServiceAudience:      "platform-mihomo-service",
		DiscoveryType:        "static",
		Endpoint:             endpoint,
		Enabled:              true,
		SupportedActionsJSON: `["bind_credential"]`,
		CredentialSchemaJSON: `{"type":"object"}`,
	}).Error)
}

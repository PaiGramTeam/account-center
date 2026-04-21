//go:build integration

package integration

import (
	"database/sql"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/model"
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

	t.Run("me routes support list create get profiles grants put grant and delete", func(t *testing.T) {
		listResp := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me/platform-accounts", nil, authHeaders(ownerAccessToken))
		require.Equal(t, http.StatusOK, listResp.Code, listResp.Body.String())
		listData := decodeResponseData(t, listResp)
		items, ok := listData["items"].([]any)
		require.True(t, ok, "expected items array, got %T", listData["items"])
		assert.Len(t, items, 1)

		createResp := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/me/platform-accounts", map[string]any{
			"platform":             "mihomo",
			"external_account_key": "cn:new-account",
			"platform_service_key": "platform-mihomo-service",
			"display_name":         "New Draft",
		}, authHeaders(ownerAccessToken))
		require.Equal(t, http.StatusCreated, createResp.Code, createResp.Body.String())
		createdData := decodeResponseData(t, createResp)
		createdID, ok := createdData["id"].(float64)
		require.True(t, ok, "expected numeric id, got %T", createdData["id"])
		assert.Equal(t, string(model.PlatformAccountBindingStatusPendingBind), createdData["status"])

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

		deleteResp := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/admin/platform-accounts/%d", deletable.ID), nil, authHeaders(adminAccessToken))
		require.Equal(t, http.StatusNoContent, deleteResp.Code, deleteResp.Body.String())
	})

	_ = viewerID
}

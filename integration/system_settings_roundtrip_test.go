//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"paigram/internal/model"
)

func TestSystemSettingsRoundTrip(t *testing.T) {
	stack := newIntegrationStack(t)
	userID, accessToken, _, _, _ := registerAndLogin(t, stack, "system-settings-admin-"+time.Now().Format("20060102150405.000000")+"@example.com", "AdminPass123!")
	grantAdminRoleToUser(t, stack, userID)

	patchSiteResp := performJSONRequest(t, stack.Router, http.MethodPatch, "/api/v1/admin/system/settings/site", map[string]any{
		"site_name":     "PaiGram",
		"site_domain":   "account.example.com",
		"support_email": "support@example.com",
	}, authHeaders(accessToken))
	require.Equal(t, http.StatusOK, patchSiteResp.Code, patchSiteResp.Body.String())

	getSiteResp := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/admin/system/settings/site", nil, authHeaders(accessToken))
	require.Equal(t, http.StatusOK, getSiteResp.Code, getSiteResp.Body.String())
	siteData := decodeResponseData(t, getSiteResp)
	require.Equal(t, "site", siteData["domain"])
	settings, ok := siteData["settings"].(map[string]any)
	require.True(t, ok, "expected settings object, got %T", siteData["settings"])
	require.Equal(t, "PaiGram", settings["site_name"])
	require.Equal(t, "account.example.com", settings["site_domain"])
	require.Equal(t, "support@example.com", settings["support_email"])

	patchAuthControlsResp := performJSONRequest(t, stack.Router, http.MethodPatch, "/api/v1/admin/system/auth-controls", map[string]any{
		"require_email_verification_login": true,
		"allow_password_login":             true,
		"allow_oauth_login":                true,
		"session_fresh_age_seconds":        float64(900),
	}, authHeaders(accessToken))
	require.Equal(t, http.StatusOK, patchAuthControlsResp.Code, patchAuthControlsResp.Body.String())

	getAuthControlsResp := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/admin/system/auth-controls", nil, authHeaders(accessToken))
	require.Equal(t, http.StatusOK, getAuthControlsResp.Code, getAuthControlsResp.Body.String())
	authControls := decodeResponseData(t, getAuthControlsResp)
	require.Equal(t, "auth_controls", authControls["domain"])
	authSettings, ok := authControls["settings"].(map[string]any)
	require.True(t, ok, "expected auth settings object, got %T", authControls["settings"])
	require.Equal(t, true, authSettings["require_email_verification_login"])
	require.Equal(t, float64(900), authSettings["session_fresh_age_seconds"])

	legalResp := performJSONRequest(t, stack.Router, http.MethodPatch, "/api/v1/admin/system/settings/legal", map[string]any{
		"documents": []map[string]any{
			{
				"document_type": "terms",
				"version":       "2026-04-01",
				"title":         "Terms of Service v1",
				"content":       "These were the previous terms.",
				"published":     false,
			},
			{
				"document_type": "terms",
				"version":       "2026-04-19",
				"title":         "Terms of Service",
				"content":       "These are the terms.",
				"published":     true,
			},
			{
				"document_type": "privacy",
				"version":       "2026-04-19",
				"title":         "Privacy Policy",
				"content":       "This is the privacy policy.",
				"published":     true,
			},
		},
	}, authHeaders(accessToken))
	require.Equal(t, http.StatusOK, legalResp.Code, legalResp.Body.String())

	getLegalResp := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/admin/system/settings/legal", nil, authHeaders(accessToken))
	require.Equal(t, http.StatusOK, getLegalResp.Code, getLegalResp.Body.String())
	legalData := decodeResponseData(t, getLegalResp)
	documents, ok := legalData["documents"].([]any)
	require.True(t, ok, "expected documents array, got %T", legalData["documents"])
	require.Len(t, documents, 3)
	firstLegalDoc, ok := documents[0].(map[string]any)
	require.True(t, ok, "expected legal document object, got %T", documents[0])
	require.Equal(t, "privacy", firstLegalDoc["document_type"])
	secondLegalDoc, ok := documents[1].(map[string]any)
	require.True(t, ok, "expected legal document object, got %T", documents[1])
	require.Equal(t, "2026-04-19", secondLegalDoc["version"])
	thirdLegalDoc, ok := documents[2].(map[string]any)
	require.True(t, ok, "expected legal document object, got %T", documents[2])
	require.Equal(t, "2026-04-01", thirdLegalDoc["version"])
	require.Equal(t, false, thirdLegalDoc["published"])

	var configEntry model.SystemConfigEntry
	require.NoError(t, stack.DB.Where("config_domain = ?", "site").First(&configEntry).Error)
	var storedSite map[string]any
	require.NoError(t, json.Unmarshal([]byte(configEntry.PayloadJSON), &storedSite))
	require.Equal(t, "account.example.com", storedSite["site_domain"])

	var legalCount int64
	require.NoError(t, stack.DB.Model(&model.LegalDocument{}).Count(&legalCount).Error)
	require.Equal(t, int64(3), legalCount)
}

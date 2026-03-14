//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/model"
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

	addEmailRes := performJSONRequest(t, stack.Router, http.MethodPost, fmt.Sprintf("/api/v1/profiles/%d/emails", userID), map[string]any{
		"email": fmt.Sprintf("alias-%d@example.com", userID),
	}, headers)
	require.Equal(t, http.StatusCreated, addEmailRes.Code, addEmailRes.Body.String())

	devicesRes := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/profiles/%d/devices", userID), nil, headers)
	require.Equal(t, http.StatusOK, devicesRes.Code, devicesRes.Body.String())

	changePasswordRes := performJSONRequest(t, stack.Router, http.MethodPost, fmt.Sprintf("/api/v1/profiles/%d/password/change", userID), map[string]any{
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

	userID, accessToken, refreshToken, _, password := registerVerifyAndLogin(t, stack, "freshness")
	session := requireSessionForRefreshToken(t, stack.DB, refreshToken)
	require.NoError(t, stack.DB.Model(&model.UserSession{}).Where("id = ?", session.ID).Update("created_at", time.Now().UTC().Add(-10*time.Minute)).Error)

	staleRes := performJSONRequest(t, stack.Router, http.MethodPost, fmt.Sprintf("/api/v1/profiles/%d/password/change", userID), map[string]any{
		"old_password": password,
		"new_password": password + "-stale",
	}, authHeaders(accessToken))
	require.Equal(t, http.StatusForbidden, staleRes.Code, staleRes.Body.String())
	assert.Equal(t, "SESSION_NOT_FRESH", decodeErrorCode(t, staleRes))
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
	errorData := payload["error"].(map[string]any)
	code, _ := errorData["code"].(string)
	return code
}

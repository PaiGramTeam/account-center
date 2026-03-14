//go:build integration

package integration

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/model"
)

func TestAuthFlowRegisterVerifyLoginRefreshLogout(t *testing.T) {
	stack := newIntegrationStack(t)

	registerRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":        "integration@example.com",
		"password":     "Password123!",
		"display_name": "Integration Tester",
		"locale":       "en_US",
	}, nil)
	require.Equal(t, http.StatusCreated, registerRes.Code, registerRes.Body.String())
	registerData := decodeResponseData(t, registerRes)
	verificationToken, ok := registerData["verification_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, verificationToken)

	verifyRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/verify-email", map[string]any{
		"email": "integration@example.com",
		"token": verificationToken,
	}, nil)
	require.Equal(t, http.StatusOK, verifyRes.Code, verifyRes.Body.String())

	loginHeaders := map[string]string{"User-Agent": "IntegrationTest/1.0"}
	loginRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "integration@example.com",
		"password": "Password123!",
	}, loginHeaders)
	require.Equal(t, http.StatusOK, loginRes.Code, loginRes.Body.String())
	loginData := decodeResponseData(t, loginRes)
	accessToken, ok := loginData["access_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, accessToken)
	refreshToken, ok := loginData["refresh_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, refreshToken)

	session := requireSessionForRefreshToken(t, stack.DB, refreshToken)
	require.NoError(t, stack.DB.Model(&model.UserSession{}).Where("id = ?", session.ID).Update("updated_at", time.Now().UTC().Add(-6*time.Second)).Error)

	refreshRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token": refreshToken,
	}, nil)
	require.Equal(t, http.StatusOK, refreshRes.Code, refreshRes.Body.String())
	refreshData := decodeResponseData(t, refreshRes)
	newRefreshToken, ok := refreshData["refresh_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, newRefreshToken)
	assert.NotEqual(t, refreshToken, newRefreshToken)

	logoutRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/logout", map[string]any{
		"token": newRefreshToken,
	}, nil)
	require.Equal(t, http.StatusOK, logoutRes.Code, logoutRes.Body.String())

	reuseRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token": newRefreshToken,
	}, nil)
	require.Equal(t, http.StatusUnauthorized, reuseRes.Code, reuseRes.Body.String())

	var user model.User
	require.NoError(t, stack.DB.Where("id = ?", uint64(loginData["user_id"].(float64))).First(&user).Error)
	assert.Equal(t, model.UserStatusActive, user.Status)
}

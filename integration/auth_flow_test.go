//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/config"
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

func TestAuthMiddlewareRefreshesSlidingSessionExpiryAfterUpdateAge(t *testing.T) {
	stack := newIntegrationStackWithConfig(t, func(cfg *config.Config) {
		cfg.Auth.SessionUpdateAgeSeconds = 1
	})

	_, accessToken, refreshToken, _, _ := registerVerifyAndLogin(t, stack, "sliding-session")
	session := requireSessionForRefreshToken(t, stack.DB, refreshToken)

	staleUpdatedAt := time.Now().UTC().Add(-2 * time.Second)
	require.NoError(t, stack.DB.Model(&model.UserSession{}).
		Where("id = ?", session.ID).
		Update("updated_at", staleUpdatedAt).Error)

	time.Sleep(20 * time.Millisecond)

	res := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me", nil, authHeaders(accessToken))
	require.Equal(t, http.StatusOK, res.Code, res.Body.String())

	refreshed := requireSessionForRefreshToken(t, stack.DB, refreshToken)
	assert.True(t, refreshed.UpdatedAt.After(staleUpdatedAt), "expected updated_at to move forward")
	assert.True(t, refreshed.AccessExpiry.After(session.AccessExpiry), "expected access expiry to extend")
	assert.True(t, refreshed.RefreshExpiry.After(session.RefreshExpiry), "expected refresh expiry to extend")
}

func TestAuthMiddlewareRefreshesSlidingSessionExpiryWhenUpdateAgeIsUnset(t *testing.T) {
	stack := newIntegrationStackWithConfig(t, func(cfg *config.Config) {
		cfg.Auth.SessionUpdateAgeSeconds = 0
	})

	_, accessToken, refreshToken, _, _ := registerVerifyAndLogin(t, stack, "sliding-session-default")
	session := requireSessionForRefreshToken(t, stack.DB, refreshToken)

	staleUpdatedAt := time.Now().UTC().Add(-25 * time.Hour)
	require.NoError(t, stack.DB.Model(&model.UserSession{}).
		Where("id = ?", session.ID).
		Update("updated_at", staleUpdatedAt).Error)

	time.Sleep(20 * time.Millisecond)

	res := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me", nil, authHeaders(accessToken))
	require.Equal(t, http.StatusOK, res.Code, res.Body.String())

	refreshed := requireSessionForRefreshToken(t, stack.DB, refreshToken)
	assert.True(t, refreshed.UpdatedAt.After(staleUpdatedAt), "expected updated_at to move forward")
	assert.True(t, refreshed.AccessExpiry.After(session.AccessExpiry), "expected access expiry to extend")
	assert.True(t, refreshed.RefreshExpiry.After(session.RefreshExpiry), "expected refresh expiry to extend")
}

func TestAuthMiddlewareUsesDBWhenCachedAccessExpiryIsStale(t *testing.T) {
	stack := newIntegrationStackWithConfig(t, func(cfg *config.Config) {
		cfg.Auth.AccessTokenTTLSeconds = 2
		cfg.Auth.RefreshTokenTTLSeconds = 60
		cfg.Auth.SessionUpdateAgeSeconds = 1
	})

	_, accessToken, refreshToken, _, _ := registerVerifyAndLogin(t, stack, "stale-cache-expiry")
	session := requireSessionForRefreshToken(t, stack.DB, refreshToken)

	staleUpdatedAt := time.Now().UTC().Add(-2 * time.Second)
	require.NoError(t, stack.DB.Model(&model.UserSession{}).
		Where("id = ?", session.ID).
		Update("updated_at", staleUpdatedAt).Error)

	untilFirstRequest := time.Until(session.AccessExpiry.Add(-500 * time.Millisecond))
	if untilFirstRequest > 0 {
		time.Sleep(untilFirstRequest)
	}

	firstRes := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me", nil, authHeaders(accessToken))
	require.Equal(t, http.StatusOK, firstRes.Code, firstRes.Body.String())

	refreshed := requireSessionForRefreshToken(t, stack.DB, refreshToken)
	assert.True(t, refreshed.AccessExpiry.After(session.AccessExpiry), "expected db expiry to extend")

	staleCachePayload, err := json.Marshal(struct {
		SessionID     uint64     `json:"session_id"`
		UserID        uint64     `json:"user_id"`
		AccessExpiry  time.Time  `json:"access_expiry"`
		RefreshExpiry time.Time  `json:"refresh_expiry"`
		RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	}{
		SessionID:     refreshed.ID,
		UserID:        refreshed.UserID,
		AccessExpiry:  session.AccessExpiry,
		RefreshExpiry: refreshed.RefreshExpiry,
	})
	require.NoError(t, err)
	require.NoError(t, stack.Redis.Set(context.Background(), fmt.Sprintf("%s:session:access:%s", stack.RedisPrefix, accessToken), staleCachePayload, time.Minute).Err())

	untilOriginalExpiryPasses := time.Until(session.AccessExpiry.Add(200 * time.Millisecond))
	if untilOriginalExpiryPasses > 0 {
		time.Sleep(untilOriginalExpiryPasses)
	}

	secondRes := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me", nil, authHeaders(accessToken))
	require.Equal(t, http.StatusOK, secondRes.Code, secondRes.Body.String())
}

func TestRevokedSessionCannotBeReusedWhileAccessTokenIsCached(t *testing.T) {
	stack := newIntegrationStack(t)

	_, accessToken, refreshToken, _, _ := registerVerifyAndLogin(t, stack, "revoke-cached-access")
	session := requireSessionForRefreshToken(t, stack.DB, refreshToken)

	precheckRes := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me", nil, authHeaders(accessToken))
	require.Equal(t, http.StatusOK, precheckRes.Code, precheckRes.Body.String())

	revokeRes := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/me/sessions/%d", session.ID), nil, authHeaders(accessToken))
	require.Equal(t, http.StatusNoContent, revokeRes.Code, revokeRes.Body.String())

	reuseRes := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me", nil, authHeaders(accessToken))
	require.Equal(t, http.StatusUnauthorized, reuseRes.Code, reuseRes.Body.String())
	assert.Equal(t, "SESSION_REVOKED", decodeErrorCode(t, reuseRes))
}

func TestRevokeAllSessionsPreservesCurrentSessionAndRevokesOtherCachedSessions(t *testing.T) {
	stack := newIntegrationStack(t)

	_, currentAccessToken, currentRefreshToken, email, password := registerVerifyAndLogin(t, stack, "revoke-all")
	currentSession := requireSessionForRefreshToken(t, stack.DB, currentRefreshToken)

	otherLoginRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    email,
		"password": password,
	}, map[string]string{"User-Agent": "IntegrationSecurityRoutes/secondary"})
	require.Equal(t, http.StatusOK, otherLoginRes.Code, otherLoginRes.Body.String())
	otherLoginData := decodeResponseData(t, otherLoginRes)
	otherAccessToken := otherLoginData["access_token"].(string)
	otherRefreshToken := otherLoginData["refresh_token"].(string)
	otherSession := requireSessionForRefreshToken(t, stack.DB, otherRefreshToken)
	require.NotEqual(t, currentSession.ID, otherSession.ID)

	currentPrecheckRes := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me", nil, authHeaders(currentAccessToken))
	require.Equal(t, http.StatusOK, currentPrecheckRes.Code, currentPrecheckRes.Body.String())
	otherPrecheckRes := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me", nil, authHeaders(otherAccessToken))
	require.Equal(t, http.StatusOK, otherPrecheckRes.Code, otherPrecheckRes.Body.String())

	revokeOtherRes := performJSONRequest(t, stack.Router, http.MethodDelete, fmt.Sprintf("/api/v1/me/sessions/%d", otherSession.ID), nil, authHeaders(currentAccessToken))
	require.Equal(t, http.StatusNoContent, revokeOtherRes.Code, revokeOtherRes.Body.String())

	currentStillWorksRes := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me", nil, authHeaders(currentAccessToken))
	require.Equal(t, http.StatusOK, currentStillWorksRes.Code, currentStillWorksRes.Body.String())

	revokedOtherRes := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me", nil, authHeaders(otherAccessToken))
	require.Equal(t, http.StatusUnauthorized, revokedOtherRes.Code, revokedOtherRes.Body.String())
	assert.Equal(t, "SESSION_REVOKED", decodeErrorCode(t, revokedOtherRes))

	var refreshedCurrent model.UserSession
	require.NoError(t, stack.DB.First(&refreshedCurrent, currentSession.ID).Error)
	assert.False(t, refreshedCurrent.RevokedAt.Valid)

	var refreshedOther model.UserSession
	require.NoError(t, stack.DB.First(&refreshedOther, otherSession.ID).Error)
	assert.True(t, refreshedOther.RevokedAt.Valid)
}

func TestRefreshTokenSucceedsImmediatelyAfterLogin(t *testing.T) {
	stack := newIntegrationStack(t)

	_, _, refreshToken, _, _ := registerVerifyAndLogin(t, stack, "immediate-refresh")

	refreshRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token": refreshToken,
	}, nil)
	require.Equal(t, http.StatusOK, refreshRes.Code, refreshRes.Body.String())

	refreshData := decodeResponseData(t, refreshRes)
	newRefreshToken, ok := refreshData["refresh_token"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, newRefreshToken)
	assert.NotEqual(t, refreshToken, newRefreshToken)
}

func TestOldRefreshTokenRejectedAfterSuccessfulRotationEvenAfterDelay(t *testing.T) {
	stack := newIntegrationStack(t)

	_, _, refreshToken, _, _ := registerVerifyAndLogin(t, stack, "refresh-rotation")

	refreshRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token": refreshToken,
	}, nil)
	require.Equal(t, http.StatusOK, refreshRes.Code, refreshRes.Body.String())

	time.Sleep(6 * time.Second)

	replayRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token": refreshToken,
	}, nil)
	require.Equal(t, http.StatusUnauthorized, replayRes.Code, replayRes.Body.String())
}

func TestOldAccessTokenRejectedAfterRefreshRotation(t *testing.T) {
	stack := newIntegrationStack(t)

	_, accessToken, refreshToken, _, _ := registerVerifyAndLogin(t, stack, "access-rotation")

	precheckRes := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me", nil, authHeaders(accessToken))
	require.Equal(t, http.StatusOK, precheckRes.Code, precheckRes.Body.String())

	refreshRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token": refreshToken,
	}, nil)
	require.Equal(t, http.StatusOK, refreshRes.Code, refreshRes.Body.String())

	oldAccessReuseRes := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me", nil, authHeaders(accessToken))
	require.Equal(t, http.StatusUnauthorized, oldAccessReuseRes.Code, oldAccessReuseRes.Body.String())
}

func TestLogoutByRefreshTokenInvalidatesCachedAccessToken(t *testing.T) {
	stack := newIntegrationStack(t)

	_, accessToken, refreshToken, _, _ := registerVerifyAndLogin(t, stack, "logout-refresh")

	precheckRes := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me", nil, authHeaders(accessToken))
	require.Equal(t, http.StatusOK, precheckRes.Code, precheckRes.Body.String())

	logoutRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/logout", map[string]any{
		"token": refreshToken,
	}, nil)
	require.Equal(t, http.StatusOK, logoutRes.Code, logoutRes.Body.String())

	reuseRes := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me", nil, authHeaders(accessToken))
	require.Equal(t, http.StatusUnauthorized, reuseRes.Code, reuseRes.Body.String())
	assert.Equal(t, "SESSION_REVOKED", decodeErrorCode(t, reuseRes))
}

func TestRapidRefreshReplayInvalidatesCachedAccessToken(t *testing.T) {
	stack := newIntegrationStack(t)

	_, _, refreshToken, _, _ := registerVerifyAndLogin(t, stack, "rapid-refresh-access")

	refreshRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token": refreshToken,
	}, nil)
	require.Equal(t, http.StatusOK, refreshRes.Code, refreshRes.Body.String())
	refreshData := decodeResponseData(t, refreshRes)
	newAccessToken := refreshData["access_token"].(string)
	newRefreshToken := refreshData["refresh_token"].(string)

	precheckRes := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me", nil, authHeaders(newAccessToken))
	require.Equal(t, http.StatusOK, precheckRes.Code, precheckRes.Body.String())

	replayRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/refresh", map[string]any{
		"refresh_token": newRefreshToken,
	}, nil)
	require.Equal(t, http.StatusUnauthorized, replayRes.Code, replayRes.Body.String())
	assert.Equal(t, "RAPID_REFRESH_DETECTED", decodeErrorCode(t, replayRes))

	reuseRes := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/me", nil, authHeaders(newAccessToken))
	require.Equal(t, http.StatusUnauthorized, reuseRes.Code, reuseRes.Body.String())
	assert.Equal(t, "SESSION_REVOKED", decodeErrorCode(t, reuseRes))
}

func TestConcurrentRefreshAllowsOnlyOneSuccessfulRotation(t *testing.T) {
	stack := newIntegrationStack(t)

	_, _, refreshToken, _, _ := registerVerifyAndLogin(t, stack, "concurrent-refresh")

	type result struct {
		code int
		body string
	}

	results := make([]result, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	for i := range results {
		go func(idx int) {
			defer wg.Done()
			res := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/refresh", map[string]any{
				"refresh_token": refreshToken,
			}, nil)
			results[idx] = result{code: res.Code, body: res.Body.String()}
		}(i)
	}

	wg.Wait()

	successes := 0
	unauthorized := 0
	for _, result := range results {
		switch result.code {
		case http.StatusOK:
			successes++
		case http.StatusUnauthorized:
			unauthorized++
		default:
			t.Fatalf("unexpected refresh status %d: %s", result.code, result.body)
		}
	}

	assert.Equal(t, 1, successes)
	assert.Equal(t, 1, unauthorized)
}

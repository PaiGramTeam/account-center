//go:build integration

package integration

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/config"
)

func TestAuthLoginRejectsUserEnumerationSignals(t *testing.T) {
	stack := newIntegrationStack(t)
	_, _, _, email, _ := registerVerifyAndLogin(t, stack, "login-enum")

	unknownEmailRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "missing@example.com",
		"password": "Password123!",
	}, nil)
	wrongPasswordRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    email,
		"password": "WrongPassword123!",
	}, nil)

	require.Equal(t, http.StatusUnauthorized, unknownEmailRes.Code, unknownEmailRes.Body.String())
	require.Equal(t, http.StatusUnauthorized, wrongPasswordRes.Code, wrongPasswordRes.Body.String())
	assert.JSONEq(t, unknownEmailRes.Body.String(), wrongPasswordRes.Body.String())
}

func TestAuthLoginRateLimitByIP(t *testing.T) {
	stack := newIntegrationStackWithConfig(t, func(cfg *config.Config) {
		cfg.RateLimit.Auth.Login = "2-M"
	})
	_, _, _, email, _ := registerVerifyAndLogin(t, stack, "login-rate-limit")
	blockedIP := "198.51.100.10:12345"

	first := performJSONRequestFromIP(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    email,
		"password": "WrongPassword123!",
	}, nil, blockedIP)
	second := performJSONRequestFromIP(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    email,
		"password": "WrongPassword123!",
	}, nil, blockedIP)
	third := performJSONRequestFromIP(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    email,
		"password": "WrongPassword123!",
	}, nil, blockedIP)

	require.Equal(t, http.StatusUnauthorized, first.Code, first.Body.String())
	require.Equal(t, http.StatusUnauthorized, second.Code, second.Body.String())
	require.Equal(t, http.StatusTooManyRequests, third.Code, third.Body.String())
	assert.Contains(t, third.Body.String(), "RATE_LIMIT_EXCEEDED")
	assertRetryAfterWithinRange(t, third.Header().Get("Retry-After"), 58, 60)

	fourth := performJSONRequestFromIP(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "other@example.com",
		"password": "WrongPassword123!",
	}, nil, "198.51.100.11:12345")
	require.Equal(t, http.StatusUnauthorized, fourth.Code, fourth.Body.String())
}

func TestAuthRegisterRateLimitByIP(t *testing.T) {
	stack := newIntegrationStackWithConfig(t, func(cfg *config.Config) {
		cfg.RateLimit.Auth.Register = "2-M"
	})
	blockedIP := "198.51.100.20:12345"

	first := performJSONRequestFromIP(t, stack.Router, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":        "repeat-register@example.com",
		"password":     "Password123!",
		"display_name": "Rate Limit One",
		"locale":       "en_US",
	}, nil, blockedIP)
	second := performJSONRequestFromIP(t, stack.Router, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":        "repeat-register@example.com",
		"password":     "Password123!",
		"display_name": "Rate Limit Two",
		"locale":       "en_US",
	}, nil, blockedIP)
	third := performJSONRequestFromIP(t, stack.Router, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":        "repeat-register@example.com",
		"password":     "Password123!",
		"display_name": "Rate Limit Three",
		"locale":       "en_US",
	}, nil, blockedIP)

	require.Equal(t, http.StatusCreated, first.Code, first.Body.String())
	require.Equal(t, http.StatusConflict, second.Code, second.Body.String())
	require.Equal(t, http.StatusTooManyRequests, third.Code, third.Body.String())
	assert.Contains(t, third.Body.String(), "RATE_LIMIT_EXCEEDED")
	assertRetryAfterWithinRange(t, third.Header().Get("Retry-After"), 58, 60)

	otherEmail := performJSONRequestFromIP(t, stack.Router, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":        "another-register@example.com",
		"password":     "Password123!",
		"display_name": "Another User",
		"locale":       "en_US",
	}, nil, "198.51.100.21:12345")
	require.Equal(t, http.StatusCreated, otherEmail.Code, otherEmail.Body.String())
}

func assertRetryAfterWithinRange(t *testing.T, value string, min int, max int) {
	t.Helper()

	retryAfter, err := strconv.Atoi(value)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, retryAfter, min)
	assert.LessOrEqual(t, retryAfter, max)
}

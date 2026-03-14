//go:build integration

package integration

import (
	"net/http"
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

func TestAuthLoginRateLimitByEmail(t *testing.T) {
	stack := newIntegrationStackWithConfig(t, func(cfg *config.Config) {
		cfg.RateLimit.Auth.Login = "2-M"
	})
	_, _, _, email, _ := registerVerifyAndLogin(t, stack, "login-rate-limit")

	first := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    email,
		"password": "WrongPassword123!",
	}, nil)
	second := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    email,
		"password": "WrongPassword123!",
	}, nil)
	third := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    email,
		"password": "WrongPassword123!",
	}, nil)

	require.Equal(t, http.StatusUnauthorized, first.Code, first.Body.String())
	require.Equal(t, http.StatusUnauthorized, second.Code, second.Body.String())
	require.Equal(t, http.StatusTooManyRequests, third.Code, third.Body.String())
	assert.Equal(t, "RATE_LIMIT_EXCEEDED", decodeErrorCode(t, third))
	assert.Equal(t, "60", third.Header().Get("Retry-After"))

	fourth := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "other@example.com",
		"password": "WrongPassword123!",
	}, nil)
	require.Equal(t, http.StatusUnauthorized, fourth.Code, fourth.Body.String())
}

func TestAuthRegisterRateLimitByEmail(t *testing.T) {
	stack := newIntegrationStackWithConfig(t, func(cfg *config.Config) {
		cfg.RateLimit.Auth.Register = "2-M"
	})

	first := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":        "repeat-register@example.com",
		"password":     "Password123!",
		"display_name": "Rate Limit One",
		"locale":       "en_US",
	}, nil)
	second := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":        "repeat-register@example.com",
		"password":     "Password123!",
		"display_name": "Rate Limit Two",
		"locale":       "en_US",
	}, nil)
	third := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":        "repeat-register@example.com",
		"password":     "Password123!",
		"display_name": "Rate Limit Three",
		"locale":       "en_US",
	}, nil)

	require.Equal(t, http.StatusCreated, first.Code, first.Body.String())
	require.Equal(t, http.StatusConflict, second.Code, second.Body.String())
	require.Equal(t, http.StatusTooManyRequests, third.Code, third.Body.String())
	assert.Equal(t, "RATE_LIMIT_EXCEEDED", decodeErrorCode(t, third))
	assert.Equal(t, "60", third.Header().Get("Retry-After"))

	otherEmail := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":        "another-register@example.com",
		"password":     "Password123!",
		"display_name": "Another User",
		"locale":       "en_US",
	}, nil)
	require.Equal(t, http.StatusCreated, otherEmail.Code, otherEmail.Body.String())
}

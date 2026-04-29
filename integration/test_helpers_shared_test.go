//go:build integration

package integration

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"paigram/internal/model"
)

func decodeJSON(t *testing.T, recorder *httptest.ResponseRecorder, target any) {
	t.Helper()
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), target))
}

// markEmailVerified bypasses the email-verification HTTP flow by directly
// flipping verified_at on the user_emails row. V14 removed the
// verification_token from the registration HTTP response, so integration
// tests that need a verified user can no longer round-trip through
// /verify-email; they verify against the DB instead. This is acceptable
// because the goal of those tests is the post-verification flow, not the
// verification mechanism itself (which has its own targeted tests).
func markEmailVerified(t *testing.T, stack *integrationStack, email string) {
	t.Helper()
	now := time.Now().UTC()
	require.NoError(t, stack.DB.Model(&model.UserEmail{}).
		Where("email = ?", email).
		Updates(map[string]any{
			"verified_at":         sql.NullTime{Time: now, Valid: true},
			"verification_token":  "",
			"verification_expiry": sql.NullTime{},
		}).Error)
	require.NoError(t, stack.DB.Model(&model.User{}).
		Where("id = (SELECT user_id FROM user_emails WHERE email = ?)", email).
		Where("status = ?", model.UserStatusPending).
		Update("status", model.UserStatusActive).Error)
}

func registerAndLogin(t *testing.T, stack *integrationStack, email, password string) (uint64, string, string, string, string) {
	t.Helper()

	registerRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":        email,
		"password":     password,
		"display_name": strings.Split(email, "@")[0],
		"locale":       "en_US",
	}, nil)
	require.Equal(t, http.StatusCreated, registerRes.Code, registerRes.Body.String())

	markEmailVerified(t, stack, email)

	loginRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    email,
		"password": password,
	}, map[string]string{"User-Agent": "IntegrationAuthorityTest/1.0"})
	require.Equal(t, http.StatusOK, loginRes.Code, loginRes.Body.String())
	loginData := decodeResponseData(t, loginRes)

	userID := uint64(loginData["user_id"].(float64))
	accessToken := loginData["access_token"].(string)
	refreshToken := loginData["refresh_token"].(string)

	return userID, accessToken, refreshToken, email, password
}

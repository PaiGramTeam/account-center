package auth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"paigram/internal/config"
	"paigram/internal/model"
)

func TestForgotPassword_ExistingEmail_CreatesResetToken(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)
	createTestUser(t, db, "reset@example.com", "Password123!", true)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/forgot-password", handler.ForgotPassword)

	body, err := json.Marshal(ForgotPasswordRequest{Email: "reset@example.com"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resetToken model.PasswordResetToken
	require.NoError(t, db.Where("used_at IS NULL").First(&resetToken).Error)
	assert.NotEmpty(t, resetToken.Token)
	assert.WithinDuration(t, time.Now().Add(time.Hour), resetToken.ExpiresAt, 5*time.Second)
}

func TestResetPassword_UpdatesEmailCredentialAndRevokesSessions(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)
	user := createTestUser(t, db, "reset@example.com", "OldPassword123!", true)

	resetToken := model.PasswordResetToken{
		UserID:    user.ID,
		Token:     hashToken("reset-token"),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, db.Create(&resetToken).Error)

	session := model.UserSession{
		UserID:           user.ID,
		AccessTokenHash:  hashToken("access-token"),
		RefreshTokenHash: hashToken("refresh-token"),
		AccessExpiry:     time.Now().Add(time.Hour),
		RefreshExpiry:    time.Now().Add(24 * time.Hour),
		UserAgent:        "PasswordResetTest/1.0",
		ClientIP:         "127.0.0.1",
	}
	require.NoError(t, db.Create(&session).Error)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/reset-password", handler.ResetPassword)

	body, err := json.Marshal(ResetPasswordRequest{
		Token:       "reset-token",
		NewPassword: "NewPassword456!",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var credential model.UserCredential
	require.NoError(t, db.Where("user_id = ? AND provider = ?", user.ID, string(model.LoginTypeEmail)).First(&credential).Error)
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(credential.PasswordHash), []byte("NewPassword456!")))
	assert.Error(t, bcrypt.CompareHashAndPassword([]byte(credential.PasswordHash), []byte("OldPassword123!")))

	var usedToken model.PasswordResetToken
	require.NoError(t, db.First(&usedToken, resetToken.ID).Error)
	assert.True(t, usedToken.UsedAt.Valid)

	var sessionCount int64
	require.NoError(t, db.Model(&model.UserSession{}).Where("user_id = ?", user.ID).Count(&sessionCount).Error)
	assert.Zero(t, sessionCount)

	var deviceCount int64
	require.NoError(t, db.Model(&model.UserDevice{}).Where("user_id = ?", user.ID).Count(&deviceCount).Error)
	assert.Zero(t, deviceCount)
}

func TestForgotPassword_UnknownEmail_ReturnsGenericResponse(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/forgot-password", handler.ForgotPassword)

	body, err := json.Marshal(ForgotPasswordRequest{Email: "missing@example.com"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var tokens int64
	require.NoError(t, db.Model(&model.PasswordResetToken{}).Count(&tokens).Error)
	assert.Zero(t, tokens)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, "if the email exists, a password reset link has been sent", data["message"])
}

func TestResetPassword_InvalidToken_ReturnsBadRequest(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)
	createTestUser(t, db, "reset@example.com", "OldPassword123!", true)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/reset-password", handler.ResetPassword)

	body, err := json.Marshal(ResetPasswordRequest{
		Token:       "unknown-token",
		NewPassword: "NewPassword456!",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errorData := resp["error"].(map[string]any)
	assert.Equal(t, "INVALID_TOKEN", errorData["code"])
}

func TestResetPassword_UsedToken_IsRejected(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)
	user := createTestUser(t, db, "reset@example.com", "OldPassword123!", true)

	resetToken := model.PasswordResetToken{
		UserID:    user.ID,
		Token:     hashToken("used-token"),
		ExpiresAt: time.Now().Add(time.Hour),
		UsedAt: sql.NullTime{
			Time:  time.Now(),
			Valid: true,
		},
	}
	require.NoError(t, db.Create(&resetToken).Error)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/reset-password", handler.ResetPassword)

	body, err := json.Marshal(ResetPasswordRequest{
		Token:       "used-token",
		NewPassword: "NewPassword456!",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errorData := resp["error"].(map[string]any)
	assert.Equal(t, "INVALID_TOKEN", errorData["code"])
}

// recordedResetEmail is captured by the test seam so we can assert what URL
// the handler hands to the email layer.
type recordedResetEmail struct {
	mu      sync.Mutex
	calls   int
	to      string
	token   string
	baseURL string
}

func (r *recordedResetEmail) capture() func(ctx context.Context, to, token, baseURL string) error {
	return func(_ context.Context, to, token, baseURL string) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.calls++
		r.to = to
		r.token = token
		r.baseURL = baseURL
		return nil
	}
}

// waitFor polls cond up to total, returning true when cond is satisfied. The
// password-reset handler dispatches its email send in a goroutine to keep
// response latency uniform regardless of whether the email is real or not,
// so tests need a brief settling window.
func waitFor(total time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(total)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

func TestForgotPassword_BaseURLNotFromOriginHeader(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)
	handler.frontendCfg = config.FrontendConfig{BaseURL: "https://app.example.com"}
	rec := &recordedResetEmail{}
	handler.sendPasswordResetEmail = rec.capture()
	createTestUser(t, db, "v2@example.com", "Password123!", true)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/forgot-password", handler.ForgotPassword)

	body, err := json.Marshal(ForgotPasswordRequest{Email: "v2@example.com"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// SECURITY: this header MUST NOT influence the reset URL — that's the
	// V2 host-header injection vulnerability we are guarding against.
	req.Header.Set("Origin", "https://attacker.example")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	require.True(t, waitFor(time.Second, func() bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return rec.calls == 1
	}), "expected exactly one password-reset email dispatch")

	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Equal(t, "https://app.example.com", rec.baseURL)
	assert.NotContains(t, rec.baseURL, "attacker.example")
	assert.Equal(t, "v2@example.com", rec.to)
	assert.NotEmpty(t, rec.token)
}

func TestForgotPassword_NoEmailWhenBaseURLEmpty(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)
	// Empty BaseURL — fail-closed: no email sent, no fallback to Origin.
	handler.frontendCfg = config.FrontendConfig{BaseURL: ""}
	rec := &recordedResetEmail{}
	handler.sendPasswordResetEmail = rec.capture()
	createTestUser(t, db, "v2-empty@example.com", "Password123!", true)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/forgot-password", handler.ForgotPassword)

	body, err := json.Marshal(ForgotPasswordRequest{Email: "v2-empty@example.com"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://attacker.example")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Generic 200 even though config is broken — don't leak internals.
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Wait briefly, then assert no dispatch happened.
	time.Sleep(50 * time.Millisecond)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Zero(t, rec.calls, "no email should be dispatched when BaseURL is empty")
}

func TestForgotPassword_TrailingSlashTrimmedFromBaseURL(t *testing.T) {
	// Defensive: configs sometimes have trailing slashes. Trimming is part of
	// the V2 fix so the resulting URL doesn't end up with "//reset-password".
	db := setupTestDB(t)
	handler := setupTestHandler(db)
	handler.frontendCfg = config.FrontendConfig{BaseURL: "https://app.example.com/"}
	rec := &recordedResetEmail{}
	handler.sendPasswordResetEmail = rec.capture()
	createTestUser(t, db, "v2-slash@example.com", "Password123!", true)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/forgot-password", handler.ForgotPassword)

	body, err := json.Marshal(ForgotPasswordRequest{Email: "v2-slash@example.com"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	require.True(t, waitFor(time.Second, func() bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return rec.calls == 1
	}))
	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Equal(t, "https://app.example.com", rec.baseURL)
	assert.False(t, strings.HasSuffix(rec.baseURL, "/"))
}

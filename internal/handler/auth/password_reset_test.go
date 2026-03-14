package auth

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

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

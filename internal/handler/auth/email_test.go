package auth

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/crypto"
	"paigram/internal/handler/shared"
	"paigram/internal/model"
	"paigram/internal/sessioncache"
	"paigram/internal/testutil"
)

func setupTestDB(t *testing.T) *gorm.DB {
	// Initialize encryption for tests
	testKey := make([]byte, 32)
	_, err := rand.Read(testKey)
	require.NoError(t, err)
	err = crypto.SetEncryptionKey(testKey)
	require.NoError(t, err)

	db := testutil.OpenMySQLTestDB(t, "auth_email",
		&model.User{},
		&model.UserProfile{},
		&model.UserCredential{},
		&model.UserEmail{},
		&model.UserSession{},
		&model.UserTwoFactor{},
		&model.LoginAudit{},
		&model.AuditLog{},
	)

	return db
}

func setupTestHandler(db *gorm.DB) *Handler {
	cfg := config.AuthConfig{
		AccessTokenTTLSeconds:         900,
		RefreshTokenTTLSeconds:        604800,
		RequireEmailVerificationLogin: false,
		EmailVerificationTTLSeconds:   86400,
	}

	sessionCache := sessioncache.NewNoopStore()

	return &Handler{
		db:           db,
		cfg:          cfg,
		sessionCache: sessionCache,
	}
}

func createTestUser(t *testing.T, db *gorm.DB, email, password string, verified bool) *model.User {
	passwordHash, err := hashPassword(password, DefaultBcryptCost)
	require.NoError(t, err)

	user := model.User{
		PrimaryLoginType: model.LoginTypeEmail,
		Status:           model.UserStatusActive,
	}
	require.NoError(t, db.Create(&user).Error)

	profile := model.UserProfile{
		UserID:      user.ID,
		DisplayName: "Test User",
		Locale:      "en_US",
	}
	require.NoError(t, db.Create(&profile).Error)

	credential := model.UserCredential{
		UserID:            user.ID,
		Provider:          string(model.LoginTypeEmail),
		ProviderAccountID: email,
		PasswordHash:      passwordHash,
	}
	require.NoError(t, db.Create(&credential).Error)

	verifiedAt := sql.NullTime{}
	if verified {
		verifiedAt = shared.MakeNullTime(time.Now().UTC())
	}

	emailRecord := model.UserEmail{
		UserID:     user.ID,
		Email:      email,
		IsPrimary:  true,
		VerifiedAt: verifiedAt,
	}
	require.NoError(t, db.Create(&emailRecord).Error)

	return &user
}

func enable2FAForUser(t *testing.T, db *gorm.DB, userID uint64) (secret string, backupCodes []string) {
	// Generate TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Paigram",
		AccountName: "test@example.com",
	})
	require.NoError(t, err)

	secret = key.Secret()

	// Generate and hash backup codes
	backupCodes = []string{"12345678", "87654321", "11111111", "22222222", "33333333", "44444444", "55555555", "66666666"}
	hashedCodes := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		hashed, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		require.NoError(t, err)
		hashedCodes[i] = string(hashed)
	}

	backupCodesJSON, err := json.Marshal(hashedCodes)
	require.NoError(t, err)

	// Encrypt the secret before storing
	encryptedSecret, err := crypto.Encrypt(secret)
	require.NoError(t, err)

	twoFactor := model.UserTwoFactor{
		UserID:      userID,
		Secret:      encryptedSecret, // Store encrypted
		BackupCodes: string(backupCodesJSON),
		EnabledAt:   time.Now().UTC(),
	}
	require.NoError(t, db.Create(&twoFactor).Error)

	return secret, backupCodes
}

func TestLoginWithEmail_Without2FA_Success(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)

	user := createTestUser(t, db, "test@example.com", "password123", true)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/login", handler.LoginWithEmail)

	reqBody := loginEmailRequest{
		Email:    "test@example.com",
		Password: "password123",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	data := response["data"].(map[string]interface{})
	assert.NotEmpty(t, data["access_token"])
	assert.NotEmpty(t, data["refresh_token"])
	assert.Equal(t, float64(user.ID), data["user_id"])
}

func TestLoginWithEmail_With2FA_NoCodeProvided_Returns2FAChallenge(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)

	user := createTestUser(t, db, "test@example.com", "password123", true)
	enable2FAForUser(t, db, user.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/login", handler.LoginWithEmail)

	reqBody := loginEmailRequest{
		Email:    "test@example.com",
		Password: "password123",
		// No TOTP code provided
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	data := response["data"].(map[string]interface{})
	assert.Equal(t, true, data["requires_totp"])
	assert.Equal(t, "2FA code required", data["message"])
	assert.Nil(t, data["access_token"])
}

func TestLoginWithEmail_With2FA_ValidTOTPCode_Success(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)

	user := createTestUser(t, db, "test@example.com", "password123", true)
	secret, _ := enable2FAForUser(t, db, user.ID)

	// Generate valid TOTP code
	totpCode, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/login", handler.LoginWithEmail)

	reqBody := loginEmailRequest{
		Email:    "test@example.com",
		Password: "password123",
		TOTPCode: totpCode,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	data := response["data"].(map[string]interface{})
	assert.NotEmpty(t, data["access_token"])
	assert.NotEmpty(t, data["refresh_token"])
	assert.Equal(t, float64(user.ID), data["user_id"])

	// Verify LastUsedAt was updated
	var twoFactor model.UserTwoFactor
	err = db.Where("user_id = ?", user.ID).First(&twoFactor).Error
	require.NoError(t, err)
	assert.True(t, twoFactor.LastUsedAt.Valid)
	assert.WithinDuration(t, time.Now(), twoFactor.LastUsedAt.Time, 5*time.Second)
}

func TestLoginWithEmail_With2FA_InvalidTOTPCode_Fails(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)

	user := createTestUser(t, db, "test@example.com", "password123", true)
	enable2FAForUser(t, db, user.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/login", handler.LoginWithEmail)

	reqBody := loginEmailRequest{
		Email:    "test@example.com",
		Password: "password123",
		TOTPCode: "000000", // Invalid code
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Verify audit log was created for failed attempt
	var auditLog model.AuditLog
	err := db.Where("user_id = ? AND action = ?", user.ID, "2fa_verification").First(&auditLog).Error
	require.NoError(t, err)
	assert.Contains(t, auditLog.Details, `"success": false`)
}

func TestLoginWithEmail_With2FA_ValidBackupCode_Success(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)

	user := createTestUser(t, db, "test@example.com", "password123", true)
	_, backupCodes := enable2FAForUser(t, db, user.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/login", handler.LoginWithEmail)

	reqBody := loginEmailRequest{
		Email:    "test@example.com",
		Password: "password123",
		TOTPCode: backupCodes[0], // Use first backup code
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	data := response["data"].(map[string]interface{})
	assert.NotEmpty(t, data["access_token"])
	assert.NotEmpty(t, data["refresh_token"])

	// Verify backup code was removed
	var twoFactor model.UserTwoFactor
	err = db.Where("user_id = ?", user.ID).First(&twoFactor).Error
	require.NoError(t, err)

	var remainingCodes []string
	err = json.Unmarshal([]byte(twoFactor.BackupCodes), &remainingCodes)
	require.NoError(t, err)
	assert.Equal(t, 7, len(remainingCodes), "Backup code should be removed after use")
}

func TestLoginWithEmail_With2FA_BackupCodeCannotBeReused(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)

	user := createTestUser(t, db, "test@example.com", "password123", true)
	_, backupCodes := enable2FAForUser(t, db, user.ID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/login", handler.LoginWithEmail)

	// First login with backup code - should succeed
	reqBody := loginEmailRequest{
		Email:    "test@example.com",
		Password: "password123",
		TOTPCode: backupCodes[0],
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second login with same backup code - should fail
	req2 := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(bodyBytes))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()

	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusUnauthorized, w2.Code)
}

func TestLoginWithEmail_With2FA_WrongPassword_NoTOTPCheck(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)

	user := createTestUser(t, db, "test@example.com", "password123", true)
	secret, _ := enable2FAForUser(t, db, user.ID)

	// Generate valid TOTP code
	totpCode, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/login", handler.LoginWithEmail)

	reqBody := loginEmailRequest{
		Email:    "test@example.com",
		Password: "wrongpassword", // Wrong password
		TOTPCode: totpCode,        // Valid TOTP code
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Verify 2FA was not checked (no audit log for 2FA verification)
	var count int64
	db.Model(&model.AuditLog{}).Where("user_id = ? AND action = ?", user.ID, "2fa_verification").Count(&count)
	assert.Equal(t, int64(0), count, "2FA should not be checked if password is wrong")
}

func TestVerifyTOTP_ValidCode(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Test",
		AccountName: "test@example.com",
	})
	require.NoError(t, err)

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)

	valid := verifyTOTP(code, key.Secret())
	assert.True(t, valid)
}

func TestVerifyTOTP_InvalidCode(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Test",
		AccountName: "test@example.com",
	})
	require.NoError(t, err)

	valid := verifyTOTP("000000", key.Secret())
	assert.False(t, valid)
}

func TestVerifyBackupCode_ValidCode(t *testing.T) {
	codes := []string{"12345678", "87654321"}
	hashedCodes := make([]string, len(codes))
	for i, code := range codes {
		hashed, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		require.NoError(t, err)
		hashedCodes[i] = string(hashed)
	}

	backupCodesJSON, err := json.Marshal(hashedCodes)
	require.NoError(t, err)

	valid, usedCode, err := verifyBackupCode("12345678", string(backupCodesJSON))
	require.NoError(t, err)
	assert.True(t, valid)
	assert.NotEmpty(t, usedCode)
}

func TestVerifyBackupCode_InvalidCode(t *testing.T) {
	codes := []string{"12345678", "87654321"}
	hashedCodes := make([]string, len(codes))
	for i, code := range codes {
		hashed, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		require.NoError(t, err)
		hashedCodes[i] = string(hashed)
	}

	backupCodesJSON, err := json.Marshal(hashedCodes)
	require.NoError(t, err)

	valid, usedCode, err := verifyBackupCode("99999999", string(backupCodesJSON))
	require.NoError(t, err)
	assert.False(t, valid)
	assert.Empty(t, usedCode)
}

func TestRemoveBackupCode(t *testing.T) {
	codes := []string{"code1", "code2", "code3"}
	backupCodesJSON, err := json.Marshal(codes)
	require.NoError(t, err)

	updatedJSON, err := removeBackupCode(string(backupCodesJSON), "code2")
	require.NoError(t, err)

	var remainingCodes []string
	err = json.Unmarshal([]byte(updatedJSON), &remainingCodes)
	require.NoError(t, err)

	assert.Equal(t, 2, len(remainingCodes))
	assert.Contains(t, remainingCodes, "code1")
	assert.Contains(t, remainingCodes, "code3")
	assert.NotContains(t, remainingCodes, "code2")
}

func TestLoginWithEmail_With2FA_AuditLogCreated(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)

	user := createTestUser(t, db, "test@example.com", "password123", true)
	secret, _ := enable2FAForUser(t, db, user.ID)

	// Generate valid TOTP code
	totpCode, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/login", handler.LoginWithEmail)

	reqBody := loginEmailRequest{
		Email:    "test@example.com",
		Password: "password123",
		TOTPCode: totpCode,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify audit log was created
	var auditLog model.AuditLog
	err = db.Where("user_id = ? AND action = ?", user.ID, "2fa_verification").First(&auditLog).Error
	require.NoError(t, err)
	assert.Equal(t, "2fa_verification", auditLog.Action)
	assert.Contains(t, auditLog.Details, `"success": true`)
	assert.Contains(t, auditLog.Details, `"method": "totp"`)
}

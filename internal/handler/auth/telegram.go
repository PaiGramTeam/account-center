package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/model"
)

// TelegramAuthData represents the data received from Telegram OAuth
type TelegramAuthData struct {
	ID        int64  `json:"id" form:"id"`
	FirstName string `json:"first_name" form:"first_name"`
	LastName  string `json:"last_name" form:"last_name"`
	Username  string `json:"username" form:"username"`
	PhotoURL  string `json:"photo_url" form:"photo_url"`
	AuthDate  int64  `json:"auth_date" form:"auth_date"`
	Hash      string `json:"hash" form:"hash"`
}

// HandleTelegramAuth handles Telegram OAuth authentication
func (h *Handler) HandleTelegramAuth(c *gin.Context) {
	var authData TelegramAuthData
	if err := c.ShouldBindJSON(&authData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request data"})
		return
	}

	// Get Telegram bot token from environment or config
	// For now, we'll expect it to be passed in the request header for security
	botToken := c.GetHeader("X-Telegram-Bot-Token")
	if botToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing bot token"})
		return
	}

	// Verify Telegram auth data
	checker := NewTelegramAuthChecker(botToken)
	if err := checker.VerifyTelegramAuth(&authData); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid telegram auth data: " + err.Error()})
		return
	}

	// Find or create user
	tx := h.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	user, err := h.findOrCreateTelegramUser(tx, &authData)
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process user"})
		return
	}

	// Issue session
	session, err := h.issueSession(tx, user.ID, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
		return
	}

	// Update last login
	now := time.Now()
	if err := tx.Model(&user).Update("last_login_at", now).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
		return
	}

	// Record login audit
	audit := model.LoginAudit{
		UserID:    sql.NullInt64{Int64: int64(user.ID), Valid: true},
		Provider:  "telegram",
		Success:   true,
		ClientIP:  c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
		Message:   "Telegram login successful",
	}

	if err := h.recordLoginAudit(tx, audit); err != nil {
		// Don't fail the login if audit fails
		// Just log the error
	}

	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to complete login"})
		return
	}

	// Build response similar to email login
	primaryEmail := ""
	for _, email := range user.Emails {
		if email.IsPrimary {
			primaryEmail = email.Email
			break
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id":           user.ID,
			"status":       user.Status,
			"display_name": user.Profile.DisplayName,
			"email":        primaryEmail,
			"avatar_url":   user.Profile.AvatarURL,
		},
		"access_token":  session.AccessToken,
		"refresh_token": session.RefreshToken,
		"token_type":    "Bearer",
		"expires_in":    h.cfg.AccessTokenTTLSeconds,
	})
}

// findOrCreateTelegramUser finds existing user or creates new one from Telegram data
func (h *Handler) findOrCreateTelegramUser(tx *gorm.DB, authData *TelegramAuthData) (*model.User, error) {
	telegramID := fmt.Sprintf("%d", authData.ID)

	// Try to find existing credential
	var credential model.UserCredential
	err := tx.Where("provider = ? AND provider_account_id = ?", "telegram", telegramID).First(&credential).Error

	if err == nil {
		// User exists, load with profile
		var user model.User
		if err := tx.Preload("Profile").Preload("Emails").First(&user, credential.UserID).Error; err != nil {
			return nil, err
		}
		return &user, nil
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	// Create new user
	user := model.User{
		PrimaryLoginType: model.LoginTypeOAuth,
		Status:           model.UserStatusActive,
	}

	if err := tx.Create(&user).Error; err != nil {
		return nil, err
	}

	// Create profile
	displayName := strings.TrimSpace(authData.FirstName + " " + authData.LastName)
	if displayName == "" {
		displayName = authData.Username
		if displayName == "" {
			displayName = fmt.Sprintf("User%d", authData.ID)
		}
	}

	profile := model.UserProfile{
		UserID:      user.ID,
		DisplayName: displayName,
		AvatarURL:   authData.PhotoURL,
		Locale:      "en_US",
	}

	if err := tx.Create(&profile).Error; err != nil {
		return nil, err
	}

	// Create credential
	metadata := fmt.Sprintf(`{"telegram_id":%d,"username":"%s"}`, authData.ID, authData.Username)
	credential = model.UserCredential{
		UserID:            user.ID,
		Provider:          "telegram",
		ProviderAccountID: telegramID,
		Metadata:          metadata,
	}

	if err := tx.Create(&credential).Error; err != nil {
		return nil, err
	}

	// Create email if username exists (as username@telegram.local)
	if authData.Username != "" {
		now := time.Now()
		email := model.UserEmail{
			UserID:    user.ID,
			Email:     fmt.Sprintf("%s@telegram.local", strings.ToLower(authData.Username)),
			IsPrimary: true,
			VerifiedAt: sql.NullTime{
				Time:  now,
				Valid: true,
			},
		}

		if err := tx.Create(&email).Error; err != nil {
			// If email creation fails, continue anyway
			// This might happen if the email already exists
		}
	}

	// Reload user with associations
	tx.Preload("Profile").Preload("Emails").First(&user, user.ID)

	return &user, nil
}

// TelegramAuthChecker verifies Telegram OAuth data
type TelegramAuthChecker struct {
	botToken string
}

// NewTelegramAuthChecker creates a new auth checker with bot token
func NewTelegramAuthChecker(botToken string) *TelegramAuthChecker {
	return &TelegramAuthChecker{
		botToken: botToken,
	}
}

// VerifyTelegramAuth verifies the Telegram OAuth data
func (c *TelegramAuthChecker) VerifyTelegramAuth(data *TelegramAuthData) error {
	// Check if auth is not too old (24 hours)
	if time.Now().Unix()-data.AuthDate > 86400 {
		return fmt.Errorf("auth data is too old")
	}

	// Create data check string
	dataCheckString := c.createDataCheckString(data)

	// Calculate expected hash
	secretKey := c.calculateSecretKey()
	expectedHash := c.calculateHash(dataCheckString, secretKey)

	// Compare hashes
	if expectedHash != data.Hash {
		return fmt.Errorf("invalid hash: expected %s, got %s", expectedHash, data.Hash)
	}

	return nil
}

// createDataCheckString creates the data check string from auth data
func (c *TelegramAuthChecker) createDataCheckString(data *TelegramAuthData) string {
	// Create map of all fields except hash
	fields := make(map[string]string)

	if data.AuthDate != 0 {
		fields["auth_date"] = strconv.FormatInt(data.AuthDate, 10)
	}
	if data.FirstName != "" {
		fields["first_name"] = data.FirstName
	}
	if data.ID != 0 {
		fields["id"] = strconv.FormatInt(data.ID, 10)
	}
	if data.LastName != "" {
		fields["last_name"] = data.LastName
	}
	if data.PhotoURL != "" {
		fields["photo_url"] = data.PhotoURL
	}
	if data.Username != "" {
		fields["username"] = data.Username
	}

	// Sort keys alphabetically
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build data check string
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, fields[k]))
	}

	return strings.Join(parts, "\n")
}

// calculateSecretKey calculates SHA256 hash of bot token
func (c *TelegramAuthChecker) calculateSecretKey() []byte {
	hash := sha256.Sum256([]byte(c.botToken))
	return hash[:]
}

// calculateHash calculates HMAC-SHA256
func (c *TelegramAuthChecker) calculateHash(data string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

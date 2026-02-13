package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"paigram/internal/crypto"
	"paigram/internal/handler/shared"
	"paigram/internal/model"
	"paigram/internal/response"
	"paigram/internal/sessioncache"
)

type registerEmailRequest struct {
	Email       string `json:"email" binding:"required,email"`
	Password    string `json:"password" binding:"required,min=8,max=72"`
	DisplayName string `json:"display_name" binding:"required"`
	Locale      string `json:"locale"`
}

// swagger:route POST /api/v1/auth/register auth registerEmail
//
// Register a new user with email and password.
//
// This endpoint creates a new user account with email/password authentication.
// An email verification token is returned if email verification is enabled.
//
// Produces:
//   - application/json
//
// Responses:
//
//	201: registerEmailResponse
//	400: authErrorResponse
//	409: authErrorResponse
//	500: authErrorResponse
//
// RegisterEmail handles registration via email + password.
func (h *Handler) RegisterEmail(c *gin.Context) {
	var req registerEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = strings.Split(email, "@")[0]
	}

	var existing model.UserEmail
	if err := h.db.Where("email = ?", email).First(&existing).Error; err == nil {
		response.Conflict(c, "email already in use")
		return
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		response.InternalServerError(c, "failed to check email uniqueness")
		return
	}

	passwordHash, err := hashPassword(req.Password)
	if err != nil {
		response.InternalServerError(c, "failed to hash password")
		return
	}

	verificationToken, err := randomToken(48)
	if err != nil {
		response.InternalServerError(c, "failed to generate verification token")
		return
	}

	verificationTTL := time.Duration(h.cfg.EmailVerificationTTLSeconds) * time.Second
	if verificationTTL <= 0 {
		verificationTTL = 24 * time.Hour
	}
	verificationExpiry := time.Now().UTC().Add(verificationTTL)

	var user model.User
	err = h.db.Transaction(func(tx *gorm.DB) error {
		user = model.User{
			PrimaryLoginType: model.LoginTypeEmail,
			Status:           model.UserStatusPending,
		}

		if err := tx.Create(&user).Error; err != nil {
			return err
		}

		profile := model.UserProfile{
			UserID:      user.ID,
			DisplayName: displayName,
			Locale:      defaultLocale(req.Locale),
		}
		if err := tx.Create(&profile).Error; err != nil {
			return err
		}

		credential := model.UserCredential{
			UserID:            user.ID,
			Provider:          string(model.LoginTypeEmail),
			ProviderAccountID: email,
			PasswordHash:      passwordHash,
		}
		if err := tx.Create(&credential).Error; err != nil {
			return err
		}

		emailRecord := model.UserEmail{
			UserID:             user.ID,
			Email:              email,
			IsPrimary:          true,
			VerificationToken:  verificationToken,
			VerificationExpiry: shared.MakeNullTime(verificationExpiry),
		}
		if err := tx.Create(&emailRecord).Error; err != nil {
			return err
		}

		// Assign default "user" role
		var userRole model.Role
		if err := tx.Where("name = ?", model.RoleUser).First(&userRole).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("query default role: %w", err)
			}
			// If default role doesn't exist, log warning but don't fail registration
			log.Printf("[auth] default role '%s' not found, skipping role assignment", model.RoleUser)
		} else {
			// Assign role to user
			userRoleAssignment := model.UserRole{
				UserID: user.ID,
				RoleID: userRole.ID,
			}
			if err := tx.Create(&userRoleAssignment).Error; err != nil {
				return fmt.Errorf("assign default role: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		response.InternalServerError(c, "failed to register user")
		return
	}

	responseData := map[string]interface{}{
		"user_id":                     user.ID,
		"email":                       email,
		"verification_token":          verificationToken,
		"verification_expires_at":     verificationExpiry.Format(time.RFC3339),
		"requires_email_verification": h.cfg.RequireEmailVerificationLogin,
	}
	response.Created(c, responseData)
}

type loginEmailRequest struct {
	Email       string `json:"email" binding:"required,email"`
	Password    string `json:"password" binding:"required"`
	TOTPCode    string `json:"totp_code" binding:"omitempty,len=6"` // Optional 2FA code
	TrustDevice bool   `json:"trust_device"`                        // Trust this device for 30 days
}

// swagger:route POST /api/v1/auth/login auth loginEmail
//
// Login with email and password.
//
// Authenticates a user using email and password credentials.
// Returns JWT access and refresh tokens on successful authentication.
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: loginResponse
//	400: authErrorResponse
//	401: authErrorResponse
//	403: authErrorResponse
//	500: authErrorResponse
//
// LoginWithEmail authenticates a user via email/password.
func (h *Handler) LoginWithEmail(c *gin.Context) {
	var req loginEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))

	var emailRecord model.UserEmail
	err := h.db.
		Where("email = ?", email).
		First(&emailRecord).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Unauthorized(c, "invalid credentials")
			return
		}
		response.InternalServerError(c, "failed to load credentials")
		return
	}

	var user model.User
	err = h.db.
		Preload("Profile").
		First(&user, emailRecord.UserID).Error
	if err != nil {
		response.InternalServerError(c, "failed to load user")
		return
	}

	// Check if user is allowed to login
	if user.Status != model.UserStatusActive && user.Status != model.UserStatusPending {
		response.Forbidden(c, "account is not allowed to login")
		return
	}

	// Load user credentials
	var credential model.UserCredential
	if err := h.db.Where("user_id = ? AND provider = ?", user.ID, string(model.LoginTypeEmail)).First(&credential).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Unauthorized(c, "invalid credentials")
			return
		}
		response.InternalServerError(c, "failed to load credentials")
		return
	}

	// Verify password
	if err := comparePassword(credential.PasswordHash, req.Password); err != nil {
		log.Printf("[auth] password verification failed for email=%s: %v", email, err)
		response.Unauthorized(c, "invalid credentials")
		return
	}

	// Check email verification
	if h.cfg.RequireEmailVerificationLogin && emailRecord.VerifiedAt.Time.IsZero() {
		response.Forbidden(c, "email not verified")
		return
	}

	// Check if 2FA is enabled for this user
	var twoFactor model.UserTwoFactor
	err = h.db.Where("user_id = ?", user.ID).First(&twoFactor).Error
	has2FA := err == nil

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		response.InternalServerError(c, "failed to check 2FA status")
		return
	}

	// If 2FA is enabled, check if device is trusted
	if has2FA {
		deviceID := generateDeviceID(c.GetHeader("User-Agent"), c.ClientIP())

		// Check if this device is trusted
		var device model.UserDevice
		err := h.db.Where("user_id = ? AND device_id = ?", user.ID, deviceID).First(&device).Error
		if err == nil && device.TrustExpiry.Valid && time.Now().Before(device.TrustExpiry.Time) {
			// Device is trusted and not expired, skip 2FA
			log.Printf("[auth] trusted device login for user_id=%d device_id=%s", user.ID, deviceID)
			has2FA = false // Skip 2FA verification

			// Refresh trust expiry on successful login
			h.db.Model(&device).Update("trust_expiry", time.Now().Add(30*24*time.Hour))
		}
	}

	// If 2FA is enabled (and device not trusted), verify TOTP code or backup code
	if has2FA {
		// Check if user is temporarily locked out due to failed 2FA attempts
		if locked, remaining := h.is2FALocked(c.Request.Context(), user.ID); locked {
			response.TooManyRequests(c, fmt.Sprintf("too many failed 2FA attempts, try again in %d seconds", int(remaining.Seconds())))
			return
		}

		// Check if TOTP code was provided
		if req.TOTPCode == "" {
			// No code provided - return 2FA challenge response
			response.Success(c, map[string]interface{}{
				"requires_totp": true,
				"message":       "2FA code required",
			})
			return
		}

		// Validate TOTP code first
		// Decrypt the secret before validation
		decryptedSecret, err := crypto.Decrypt(twoFactor.Secret)
		if err != nil {
			log.Printf("[auth] failed to decrypt 2FA secret for user_id=%d: %v", user.ID, err)
			response.InternalServerError(c, "failed to verify 2FA")
			return
		}

		totpValid := verifyTOTP(req.TOTPCode, decryptedSecret)
		backupCodeValid := false
		var usedBackupCode string

		if !totpValid {
			// Try backup codes if TOTP fails
			var err error
			backupCodeValid, usedBackupCode, err = verifyBackupCode(req.TOTPCode, twoFactor.BackupCodes)
			if err != nil {
				log.Printf("[auth] error verifying backup code for user_id=%d: %v", user.ID, err)
			}
		}

		// If both TOTP and backup code fail, deny access
		if !totpValid && !backupCodeValid {
			// Track failed 2FA attempts to prevent brute force
			if err := h.track2FAFailure(c.Request.Context(), user.ID); err != nil {
				log.Printf("[auth] failed to track 2FA failure for user_id=%d: %v", user.ID, err)
			}

			// Log failed 2FA attempt
			err = h.db.Transaction(func(tx *gorm.DB) error {
				return h.logTwoFactorAudit(tx, user.ID, false, "totp_or_backup", c.ClientIP(), c.GetHeader("User-Agent"))
			})
			if err != nil {
				log.Printf("[auth] failed to log 2FA audit: %v", err)
			}

			response.Unauthorized(c, "invalid 2FA code")
			return
		}

		// 2FA verification successful - clear failed attempts counter
		h.clear2FAFailures(c.Request.Context(), user.ID)

		// If user chose to trust this device, mark it as trusted
		if req.TrustDevice {
			deviceID := generateDeviceID(c.GetHeader("User-Agent"), c.ClientIP())
			trustExpiry := time.Now().Add(30 * 24 * time.Hour) // 30 days

			// Update or create device record with trust expiry
			var device model.UserDevice
			err := h.db.Where("user_id = ? AND device_id = ?", user.ID, deviceID).First(&device).Error
			if err == gorm.ErrRecordNotFound {
				// Create new trusted device record
				deviceType, os, browser := parseUserAgent(c.GetHeader("User-Agent"))
				device = model.UserDevice{
					UserID:       user.ID,
					DeviceID:     deviceID,
					DeviceName:   fmt.Sprintf("%s on %s", browser, os),
					DeviceType:   deviceType,
					OS:           os,
					Browser:      browser,
					IP:           c.ClientIP(),
					LastActiveAt: time.Now(),
					TrustExpiry:  shared.MakeNullTime(trustExpiry),
				}
				h.db.Create(&device)
			} else if err == nil {
				// Update existing device
				h.db.Model(&device).Updates(map[string]interface{}{
					"trust_expiry":   shared.MakeNullTime(trustExpiry),
					"last_active_at": time.Now(),
					"ip":             c.ClientIP(),
				})
			}

			log.Printf("[auth] device marked as trusted for user_id=%d device_id=%s until=%s",
				user.ID, deviceID, trustExpiry.Format(time.RFC3339))
		}

		// 2FA verification successful
		// Update LastUsedAt and remove backup code if used
		err = h.db.Transaction(func(tx *gorm.DB) error {
			updates := map[string]interface{}{
				"last_used_at": shared.MakeNullTime(time.Now().UTC()),
			}

			// Remove used backup code
			if backupCodeValid && usedBackupCode != "" {
				updatedBackupCodes, err := removeBackupCode(twoFactor.BackupCodes, usedBackupCode)
				if err != nil {
					log.Printf("[auth] failed to remove backup code: %v", err)
				} else {
					updates["backup_codes"] = updatedBackupCodes
				}
			}

			if err := tx.Model(&model.UserTwoFactor{}).Where("id = ?", twoFactor.ID).Updates(updates).Error; err != nil {
				return fmt.Errorf("update 2FA record: %w", err)
			}

			// Log successful 2FA verification
			method := "totp"
			if backupCodeValid {
				method = "backup_code"
			}
			return h.logTwoFactorAudit(tx, user.ID, true, method, c.ClientIP(), c.GetHeader("User-Agent"))
		})

		if err != nil {
			log.Printf("[auth] failed to update 2FA record: %v", err)
			// Don't fail login if we can't update the record, but log it
		}
	}

	// Create session
	var sessionWithTokens *SessionWithTokens
	now := time.Now().UTC()
	err = h.db.Transaction(func(tx *gorm.DB) error {
		// Update last login time and activate pending users
		updates := map[string]interface{}{
			"last_login_at": shared.MakeNullTime(now),
		}
		if user.Status == model.UserStatusPending && (!h.cfg.RequireEmailVerificationLogin || !emailRecord.VerifiedAt.Time.IsZero()) {
			updates["status"] = model.UserStatusActive
		}

		if err := tx.Model(&model.User{}).Where("id = ?", user.ID).Updates(updates).Error; err != nil {
			return err
		}

		var err error
		sessionWithTokens, err = h.issueSession(tx, user.ID, c.ClientIP(), c.GetHeader("User-Agent"))
		if err != nil {
			return err
		}

		return h.recordLoginAudit(tx, model.LoginAudit{
			UserID:    sql.NullInt64{Int64: int64(user.ID), Valid: true},
			Provider:  string(model.LoginTypeEmail),
			Success:   true,
			ClientIP:  c.ClientIP(),
			UserAgent: c.GetHeader("User-Agent"),
			Message:   "login success",
		})
	})

	if err != nil {
		response.InternalServerError(c, "failed to create session")
		return
	}

	responseData := map[string]interface{}{
		"user_id":        user.ID,
		"access_token":   sessionWithTokens.AccessToken,
		"refresh_token":  sessionWithTokens.RefreshToken,
		"access_expiry":  sessionWithTokens.Session.AccessExpiry.Format(time.RFC3339),
		"refresh_expiry": sessionWithTokens.Session.RefreshExpiry.Format(time.RFC3339),
	}
	response.Success(c, responseData)
}

type refreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// swagger:route POST /api/v1/auth/refresh auth refreshToken
//
// Refresh access token.
//
// Exchange a valid refresh token for a new access/refresh token pair.
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: loginResponse
//	400: authErrorResponse
//	401: authErrorResponse
//	500: authErrorResponse
//
// RefreshToken exchanges a refresh token for a new pair.
func (h *Handler) RefreshToken(c *gin.Context) {
	var req refreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	ctx := context.Background()
	if revoked, err := h.sessionCache.IsRevoked(ctx, sessioncache.TokenTypeRefresh, req.RefreshToken); err != nil && !errorsIsRedisNil(err) {
		log.Printf("failed to query refresh token revocation: %v", err)
	} else if revoked {
		response.Unauthorized(c, "token revoked")
		return
	}

	var session model.UserSession
	var sessionID uint64
	if id, err := h.sessionCache.GetSessionID(ctx, sessioncache.TokenTypeRefresh, req.RefreshToken); err == nil {
		sessionID = id
	} else if err != nil && !errorsIsRedisNil(err) {
		log.Printf("failed to get session id from cache: %v", err)
	}

	now := time.Now().UTC()
	var err error
	refreshTokenHash := hashToken(req.RefreshToken)
	if sessionID > 0 {
		err = h.db.First(&session, sessionID).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = h.db.Where("refresh_token_hash = ?", refreshTokenHash).First(&session).Error
		}
	} else {
		err = h.db.Where("refresh_token_hash = ?", refreshTokenHash).First(&session).Error
	}
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.Unauthorized(c, "invalid refresh token")
			return
		}
		response.InternalServerError(c, "failed to load session")
		return
	}

	if session.RevokedAt.Valid {
		// Token已被撤销 - 可能是重用攻击！
		// 撤销该用户的所有 session 作为安全措施
		log.Printf("[security] Attempt to use revoked refresh token detected for user %d - revoking all sessions", session.UserID)

		h.db.Transaction(func(tx *gorm.DB) error {
			return tx.Model(&model.UserSession{}).
				Where("user_id = ? AND revoked_at IS NULL", session.UserID).
				Updates(map[string]interface{}{
					"revoked_at":     now,
					"revoked_reason": "token_reuse_detected",
				}).Error
		})

		response.UnauthorizedWithCode(c, "TOKEN_REUSE_DETECTED", "security violation: token reuse detected, all sessions revoked", nil)
		return
	}

	if now.After(session.RefreshExpiry) {
		response.Unauthorized(c, "refresh token expired")
		return
	}

	var user model.User
	if err := h.db.First(&user, session.UserID).Error; err != nil {
		response.InternalServerError(c, "failed to load user")
		return
	}

	prevSession := session
	var newAccessToken, newRefreshToken string

	// Check if this session was recently refreshed (within last 5 seconds)
	// This could indicate a replay attack or race condition
	if time.Since(session.UpdatedAt) < 5*time.Second {
		log.Printf("[security] Refresh token used too quickly after last refresh for session %d - possible replay attack", session.ID)

		// Revoke this session and all user sessions as a security measure
		h.db.Transaction(func(tx *gorm.DB) error {
			return tx.Model(&model.UserSession{}).
				Where("user_id = ?", session.UserID).
				Updates(map[string]interface{}{
					"revoked_at":     now,
					"revoked_reason": "rapid_refresh_detected",
				}).Error
		})

		response.UnauthorizedWithCode(c, "RAPID_REFRESH_DETECTED", "security violation: rapid token refresh detected", nil)
		return
	}

	err = h.db.Transaction(func(tx *gorm.DB) error {
		accessToken, err := randomToken(48)
		if err != nil {
			return err
		}
		refreshToken, err := randomToken(64)
		if err != nil {
			return err
		}

		// Store for later use
		newAccessToken = accessToken
		newRefreshToken = refreshToken

		accessTTL := time.Duration(h.cfg.AccessTokenTTLSeconds) * time.Second
		if accessTTL <= 0 {
			accessTTL = 15 * time.Minute
		}
		refreshTTL := time.Duration(h.cfg.RefreshTokenTTLSeconds) * time.Second
		if refreshTTL <= 0 {
			refreshTTL = 7 * 24 * time.Hour
		}

		// Update session with hashed tokens
		updates := map[string]interface{}{
			"access_token_hash":  hashToken(accessToken),
			"refresh_token_hash": hashToken(refreshToken),
			"access_expiry":      now.Add(accessTTL),
			"refresh_expiry":     now.Add(refreshTTL),
			"updated_at":         now,
		}

		if err := tx.Model(&model.UserSession{}).Where("id = ?", session.ID).Updates(updates).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		response.InternalServerError(c, "failed to refresh token")
		return
	}

	// Revoke old tokens from cache
	h.cacheRevokeSessionTokens(&prevSession, req.RefreshToken, "")

	// Reload updated session
	var newSession model.UserSession
	if err := h.db.First(&newSession, session.ID).Error; err != nil {
		response.InternalServerError(c, "failed to load updated session")
		return
	}

	// Cache new tokens
	h.cacheStoreSessionWithTokens(&newSession, newAccessToken, newRefreshToken)

	responseData := map[string]interface{}{
		"user_id":        newSession.UserID,
		"access_token":   newAccessToken,
		"refresh_token":  newRefreshToken,
		"access_expiry":  newSession.AccessExpiry.Format(time.RFC3339),
		"refresh_expiry": newSession.RefreshExpiry.Format(time.RFC3339),
	}
	response.Success(c, responseData)
}

type logoutRequest struct {
	Token string `json:"token" binding:"required"`
}

// swagger:route POST /api/v1/auth/logout auth logout
//
// Logout and revoke token.
//
// Revokes an access or refresh token, preventing further use.
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: logoutResponse
//	400: authErrorResponse
//	500: authErrorResponse
//
// Logout revokes an access or refresh token.
func (h *Handler) Logout(c *gin.Context) {
	var req logoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	var session model.UserSession
	tokenHash := hashToken(req.Token)
	err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("access_token_hash = ? OR refresh_token_hash = ?", tokenHash, tokenHash).First(&session).Error; err != nil {
			return err
		}
		if session.RevokedAt.Valid {
			return nil
		}
		return h.revokeSession(tx, &session, "user_logout")
	})

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.SuccessWithMessage(c, response.NewMessageData("already logged out"), "already logged out")
			return
		}
		response.InternalServerError(c, "failed to logout")
		return
	}

	// Revoke from cache (we have the original token from request)
	h.cacheRevokeSessionTokens(&session, req.Token, req.Token)

	response.SuccessWithMessage(c, response.NewMessageData("logout successful"), "logout successful")
}

type verifyEmailRequest struct {
	Email string `json:"email" binding:"required,email"`
	Token string `json:"token" binding:"required"`
}

// swagger:route POST /api/v1/auth/verify-email auth verifyEmail
//
// Verify email address.
//
// Verifies a user's email address using the verification token sent during registration.
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: verifyEmailResponse
//	400: authErrorResponse
//	404: authErrorResponse
//
// VerifyEmail handles email verification.
func (h *Handler) VerifyEmail(c *gin.Context) {
	var req verifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))

	err := h.db.Transaction(func(tx *gorm.DB) error {
		var emailRecord model.UserEmail
		if err := tx.Where("email = ?", email).First(&emailRecord).Error; err != nil {
			return err
		}

		if emailRecord.VerificationToken == "" {
			if emailRecord.VerifiedAt.Valid {
				return nil
			}
			return fmt.Errorf("no verification token present")
		}

		if emailRecord.VerificationToken != req.Token {
			return fmt.Errorf("invalid token")
		}

		if emailRecord.VerificationExpiry.Valid && time.Now().UTC().After(emailRecord.VerificationExpiry.Time) {
			return fmt.Errorf("verification token expired")
		}

		update := map[string]interface{}{
			"verified_at":         shared.MakeNullTime(time.Now().UTC()),
			"verification_token":  "",
			"verification_expiry": shared.ClearNullTime(),
		}
		if err := tx.Model(&model.UserEmail{}).Where("id = ?", emailRecord.ID).Updates(update).Error; err != nil {
			return err
		}

		return tx.Model(&model.User{}).
			Where("id = ? AND status = ?", emailRecord.UserID, model.UserStatusPending).
			Update("status", model.UserStatusActive).Error
	})

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFound(c, "email not found")
			return
		}
		response.BadRequest(c, err.Error())
		return
	}

	response.SuccessWithMessage(c, response.NewMessageData("email verified"), "email verified")
}

func defaultLocale(input string) string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "en_US"
	}
	return trimmed
}

// verifyTOTP validates a TOTP code against the secret
// Accepts codes from ±1 time period (±30 seconds) to account for clock skew
func verifyTOTP(code, secret string) bool {
	// Use ValidateCustom to accept codes from previous and next time window
	// This follows better-auth best practice of accepting ±1 period
	valid, err := totp.ValidateCustom(
		code,
		secret,
		time.Now(),
		totp.ValidateOpts{
			Period:    30,                // Standard 30-second period
			Skew:      1,                 // Accept ±1 time window (±30 seconds)
			Digits:    otp.DigitsSix,     // Standard 6-digit codes
			Algorithm: otp.AlgorithmSHA1, // Standard SHA1 algorithm
		},
	)
	return err == nil && valid
}

// verifyBackupCode checks if the provided code matches any backup code
// Returns true and the matched code if found
func verifyBackupCode(code, backupCodesJSON string) (bool, string, error) {
	if backupCodesJSON == "" {
		return false, "", nil
	}

	var backupCodes []string
	if err := json.Unmarshal([]byte(backupCodesJSON), &backupCodes); err != nil {
		return false, "", fmt.Errorf("unmarshal backup codes: %w", err)
	}

	// Check each backup code (they are stored as bcrypt hashes)
	for _, hashedCode := range backupCodes {
		if err := bcrypt.CompareHashAndPassword([]byte(hashedCode), []byte(code)); err == nil {
			return true, hashedCode, nil
		}
	}

	return false, "", nil
}

// removeBackupCode removes a used backup code from the list
func removeBackupCode(backupCodesJSON, usedCode string) (string, error) {
	var backupCodes []string
	if err := json.Unmarshal([]byte(backupCodesJSON), &backupCodes); err != nil {
		return "", fmt.Errorf("unmarshal backup codes: %w", err)
	}

	// Filter out the used code
	filteredCodes := make([]string, 0, len(backupCodes)-1)
	for _, code := range backupCodes {
		if code != usedCode {
			filteredCodes = append(filteredCodes, code)
		}
	}

	updatedJSON, err := json.Marshal(filteredCodes)
	if err != nil {
		return "", fmt.Errorf("marshal backup codes: %w", err)
	}

	return string(updatedJSON), nil
}

// logTwoFactorAudit creates an audit log for 2FA verification attempts
func (h *Handler) logTwoFactorAudit(tx *gorm.DB, userID uint64, success bool, method, ip, userAgent string) error {
	message := "2FA verification success"
	if !success {
		message = "2FA verification failed"
	}

	auditLog := model.AuditLog{
		UserID:    userID,
		Action:    "2fa_verification",
		Resource:  "user_two_factor",
		IP:        ip,
		UserAgent: userAgent,
		Details:   fmt.Sprintf(`{"method": "%s", "success": %t}`, method, success),
		CreatedAt: time.Now().UTC(),
	}

	if err := tx.Create(&auditLog).Error; err != nil {
		log.Printf("[auth] failed to create 2FA audit log: %v", err)
		// Don't fail the request if audit logging fails
	}

	log.Printf("[auth] %s for user_id=%d method=%s", message, userID, method)
	return nil
}

// is2FALocked checks if user is temporarily locked out due to failed 2FA attempts
// Returns true and remaining time if locked, false otherwise
func (h *Handler) is2FALocked(ctx context.Context, userID uint64) (bool, time.Duration) {
	// If Redis is not enabled, skip rate limiting
	if h.sessionCache == nil {
		return false, 0
	}

	key := fmt.Sprintf("2fa_fail:%d", userID)

	// Get current failure count
	failCount, err := h.sessionCache.IncrementCounter(ctx, key, 0)
	if err != nil {
		log.Printf("[auth] failed to check 2FA lock status: %v", err)
		return false, 0
	}

	// Lock threshold: 5 failed attempts
	const lockThreshold = 5
	const lockDuration = 15 * time.Minute

	if failCount >= lockThreshold {
		// Get TTL to determine how long until unlock
		ttl, err := h.sessionCache.GetTTL(ctx, key)
		if err != nil || ttl <= 0 {
			// If can't get TTL or already expired, not locked
			return false, 0
		}
		return true, ttl
	}

	return false, 0
}

// track2FAFailure increments the failed 2FA attempt counter
func (h *Handler) track2FAFailure(ctx context.Context, userID uint64) error {
	if h.sessionCache == nil {
		return nil
	}

	key := fmt.Sprintf("2fa_fail:%d", userID)
	const lockDuration = 15 * time.Minute

	// Increment counter with 15 minute expiry
	count, err := h.sessionCache.IncrementCounter(ctx, key, lockDuration)
	if err != nil {
		return fmt.Errorf("increment 2FA failure count: %w", err)
	}

	log.Printf("[auth] 2FA failure count for user_id=%d: %d/5", userID, count)
	return nil
}

// clear2FAFailures clears the failed attempt counter after successful 2FA
func (h *Handler) clear2FAFailures(ctx context.Context, userID uint64) {
	if h.sessionCache == nil {
		return
	}

	key := fmt.Sprintf("2fa_fail:%d", userID)
	if err := h.sessionCache.Delete(ctx, key); err != nil {
		log.Printf("[auth] failed to clear 2FA failures for user_id=%d: %v", userID, err)
	}
}

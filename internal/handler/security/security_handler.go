package security

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"paigram/internal/crypto"
	"paigram/internal/handler/shared"
	"paigram/internal/middleware"
	"paigram/internal/model"
	"paigram/internal/response"
	"paigram/internal/sessioncache"
)

// Handler manages security-related endpoints
type Handler struct {
	db           *gorm.DB
	sessionCache sessioncache.Store
}

// NewHandler creates a new security handler
func NewHandler(db *gorm.DB, cache sessioncache.Store) *Handler {
	if cache == nil {
		cache = sessioncache.NewNoopStore()
	}
	return &Handler{
		db:           db,
		sessionCache: cache,
	}
}

// RegisterRoutes binds security endpoints beneath the given route group
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	// Password management
	rg.POST("/:id/password/change", h.ChangePassword)

	// Two-factor authentication
	rg.POST("/:id/2fa/enable", h.Enable2FA)
	rg.POST("/:id/2fa/confirm", h.Confirm2FA)
	rg.POST("/:id/2fa/disable", h.Disable2FA)

	// Device management
	rg.GET("/:id/devices", h.GetDevices)
	rg.DELETE("/:id/devices/:device_id", h.RemoveDevice)
}

type changePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=72"`
}

// ChangePassword allows users to change their password
// swagger:route POST /api/v1/profiles/{id}/password/change security changePassword
//
// Change user password.
//
// Allows users to change their password. Requires old password verification.
//
// Consumes:
//   - application/json
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: changePasswordResponse
//	400: securityErrorResponse
//	401: securityErrorResponse
//	404: securityErrorResponse
//	500: securityErrorResponse
func (h *Handler) ChangePassword(c *gin.Context) {
	userID, err := parseUintID(c.Param("id"))
	if err != nil {
		response.BadRequestWithCode(c, "INVALID_USER_ID", "invalid user id", nil)
		return
	}

	// Check if the current user is changing their own password
	currentUserID, exists := middleware.GetUserID(c)
	if !exists || currentUserID != userID {
		response.ForbiddenWithCode(c, "FORBIDDEN", "can only change your own password", nil)
		return
	}

	var req changePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequestWithCode(c, "INVALID_REQUEST", err.Error(), nil)
		return
	}

	// Get user's current password hash
	var cred model.UserCredential
	err = h.db.Where("user_id = ? AND provider = ?", userID, "email").First(&cred).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			response.NotFoundWithCode(c, "NO_PASSWORD", "user does not have password authentication", nil)
			return
		}
		response.InternalServerErrorWithCode(c, "DB_ERROR", "failed to load credentials", nil)
		return
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(cred.PasswordHash), []byte(req.OldPassword)); err != nil {
		response.UnauthorizedWithCode(c, "INVALID_PASSWORD", "incorrect old password", nil)
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		response.InternalServerErrorWithCode(c, "HASH_ERROR", "failed to hash password", nil)
		return
	}

	// Update password in transaction
	err = h.db.Transaction(func(tx *gorm.DB) error {
		// Update password
		if err := tx.Model(&model.UserCredential{}).
			Where("id = ?", cred.ID).
			Update("password_hash", string(hashedPassword)).Error; err != nil {
			return err
		}

		// Log password change
		auditLog := model.AuditLog{
			UserID:     userID,
			Action:     "password_change",
			Resource:   "user_credential",
			ResourceID: cred.ID,
			IP:         c.ClientIP(),
			UserAgent:  c.GetHeader("User-Agent"),
			Details:    `{"reason": "user_requested"}`,
			CreatedAt:  time.Now(),
		}
		if err := tx.Create(&auditLog).Error; err != nil {
			return err
		}

		// Optionally revoke all sessions except current one
		// This is a security measure to log out from all other devices
		currentToken := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if currentToken != "" {
			if err := tx.Model(&model.UserSession{}).
				Where("user_id = ? AND access_token != ?", userID, currentToken).
				Update("revoked_at", gorm.Expr("NOW()")).
				Update("revoked_reason", "password_changed").Error; err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		response.InternalServerErrorWithCode(c, "UPDATE_FAILED", "failed to change password", nil)
		return
	}

	response.Success(c, gin.H{
		"message": "password changed successfully",
	})
}

// Enable2FA initiates 2FA setup
// swagger:route POST /api/v1/profiles/{id}/2fa/enable security enable2FA
//
// Enable two-factor authentication.
//
// Generates TOTP secret and QR code for 2FA setup.
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: enable2FAResponse
//	400: securityErrorResponse
//	403: securityErrorResponse
//	409: securityErrorResponse
//	500: securityErrorResponse
func (h *Handler) Enable2FA(c *gin.Context) {
	userID, err := parseUintID(c.Param("id"))
	if err != nil {
		response.BadRequestWithCode(c, "INVALID_USER_ID", "invalid user id", nil)
		return
	}

	// Check if the current user is enabling their own 2FA
	currentUserID, exists := middleware.GetUserID(c)
	if !exists || currentUserID != userID {
		response.ForbiddenWithCode(c, "FORBIDDEN", "can only enable 2FA for your own account", nil)
		return
	}

	// Check if 2FA is already enabled
	var existing model.UserTwoFactor
	err = h.db.Where("user_id = ?", userID).First(&existing).Error
	if err == nil {
		response.ConflictWithCode(c, "ALREADY_ENABLED", "2FA is already enabled", nil)
		return
	} else if err != gorm.ErrRecordNotFound {
		response.InternalServerErrorWithCode(c, "DB_ERROR", "failed to check 2FA status", nil)
		return
	}

	// Get user info for TOTP generation
	var user model.User
	if err := h.db.Preload("Profile").First(&user, userID).Error; err != nil {
		response.InternalServerErrorWithCode(c, "DB_ERROR", "failed to load user", nil)
		return
	}

	// Generate TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Paigram",
		AccountName: user.Profile.DisplayName,
	})
	if err != nil {
		response.InternalServerErrorWithCode(c, "TOTP_ERROR", "failed to generate TOTP secret", nil)
		return
	}

	// Generate backup codes (10 codes, 10 digits each following better-auth best practice)
	backupCodes := make([]string, 10)
	for i := range backupCodes {
		code := make([]byte, 5) // 5 bytes = 10 hex digits
		if _, err := rand.Read(code); err != nil {
			response.InternalServerErrorWithCode(c, "RANDOM_ERROR", "failed to generate backup codes", nil)
			return
		}
		// Generate 10-digit numeric code
		backupCodes[i] = fmt.Sprintf("%010d",
			int(code[0])<<32|int(code[1])<<24|int(code[2])<<16|int(code[3])<<8|int(code[4]))
	}

	// Store setup data in Redis with 15-minute expiry
	setupData := TwoFactorSetupData{
		Secret:      key.Secret(),
		BackupCodes: backupCodes,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(15 * time.Minute),
	}

	setupDataJSON, err := json.Marshal(setupData)
	if err != nil {
		response.InternalServerErrorWithCode(c, "JSON_ERROR", "failed to serialize setup data", nil)
		return
	}

	// Store in Redis
	ctx := context.Background()
	setupKey := fmt.Sprintf("2fa_setup:%d", userID)

	// Use a simple Set operation via the session cache
	// We'll add a helper method for this
	if err := h.store2FASetupData(ctx, setupKey, setupDataJSON, 15*time.Minute); err != nil {
		response.InternalServerErrorWithCode(c, "CACHE_ERROR", "failed to store setup data", nil)
		return
	}

	// Generate QR code URL
	qrCodeURL := key.URL()

	// Return QR code and backup codes to user (only time they'll see plaintext codes)
	response.Success(c, gin.H{
		"qr_code":      qrCodeURL,
		"secret":       key.Secret(), // Allow manual entry
		"backup_codes": backupCodes,  // Show codes for user to save
		"expires_at":   setupData.ExpiresAt.Format(time.RFC3339),
	})
}

type confirm2FARequest struct {
	Code string `json:"code" binding:"required,len=6"`
}

// Confirm2FA confirms and activates 2FA
// swagger:route POST /api/v1/profiles/{id}/2fa/confirm security confirm2FA
//
// Confirm two-factor authentication setup.
//
// Verifies TOTP code and activates 2FA for the account.
//
// Consumes:
//   - application/json
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: confirm2FAResponse
//	400: securityErrorResponse
//	401: securityErrorResponse
//	403: securityErrorResponse
//	500: securityErrorResponse
func (h *Handler) Confirm2FA(c *gin.Context) {
	userID, err := parseUintID(c.Param("id"))
	if err != nil {
		response.BadRequestWithCode(c, "INVALID_USER_ID", "invalid user id", nil)
		return
	}

	// Check if the current user is confirming their own 2FA
	currentUserID, exists := middleware.GetUserID(c)
	if !exists || currentUserID != userID {
		response.ForbiddenWithCode(c, "FORBIDDEN", "can only confirm 2FA for your own account", nil)
		return
	}

	var req confirm2FARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequestWithCode(c, "INVALID_REQUEST", err.Error(), nil)
		return
	}

	// Retrieve setup data from Redis
	ctx := context.Background()
	setupKey := fmt.Sprintf("2fa_setup:%d", userID)

	setupDataJSON, err := h.get2FASetupData(ctx, setupKey)
	if err != nil {
		response.BadRequestWithCode(c, "SETUP_EXPIRED", "2FA setup expired or not found, please start again", nil)
		return
	}

	var setupData TwoFactorSetupData
	if err := json.Unmarshal(setupDataJSON, &setupData); err != nil {
		response.InternalServerErrorWithCode(c, "JSON_ERROR", "failed to parse setup data", nil)
		return
	}

	// Check if setup data has expired
	if time.Now().After(setupData.ExpiresAt) {
		h.delete2FASetupData(ctx, setupKey)
		response.BadRequestWithCode(c, "SETUP_EXPIRED", "2FA setup expired, please start again", nil)
		return
	}

	// Verify the TOTP code with time window tolerance
	valid, err := totp.ValidateCustom(
		req.Code,
		setupData.Secret,
		time.Now(),
		totp.ValidateOpts{
			Period:    30,
			Skew:      1, // Accept ±1 period (±30 seconds)
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
	)
	valid = err == nil && valid
	if !valid {
		response.UnauthorizedWithCode(c, "INVALID_CODE", "invalid verification code", nil)
		return
	}

	// Hash backup codes before storing
	hashedCodes := make([]string, len(setupData.BackupCodes))
	for i, code := range setupData.BackupCodes {
		hashed, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			response.InternalServerErrorWithCode(c, "HASH_ERROR", "failed to hash backup codes", nil)
			return
		}
		hashedCodes[i] = string(hashed)
	}

	backupCodesJSON, _ := json.Marshal(hashedCodes)

	// Encrypt the TOTP secret before storing
	encryptedSecret, err := crypto.Encrypt(setupData.Secret)
	if err != nil {
		response.InternalServerErrorWithCode(c, "ENCRYPTION_ERROR", "failed to encrypt secret", nil)
		return
	}

	// Save 2FA configuration
	err = h.db.Transaction(func(tx *gorm.DB) error {
		// Create 2FA record
		twoFactor := model.UserTwoFactor{
			UserID:      userID,
			Secret:      encryptedSecret, // Encrypted secret
			BackupCodes: string(backupCodesJSON),
			EnabledAt:   time.Now(),
		}

		if err := tx.Create(&twoFactor).Error; err != nil {
			return err
		}

		// Log the action
		auditLog := model.AuditLog{
			UserID:     userID,
			Action:     "2fa_enabled",
			Resource:   "user_two_factor",
			ResourceID: twoFactor.ID,
			IP:         c.ClientIP(),
			UserAgent:  c.GetHeader("User-Agent"),
			CreatedAt:  time.Now(),
		}

		return tx.Create(&auditLog).Error
	})

	if err != nil {
		response.InternalServerErrorWithCode(c, "SAVE_FAILED", "failed to enable 2FA", nil)
		return
	}

	// Delete setup data from Redis after successful confirmation
	h.delete2FASetupData(ctx, setupKey)

	// Note: We don't return backup codes here as they were already shown in Enable2FA
	response.Success(c, gin.H{
		"message": "2FA enabled successfully",
	})
}

type disable2FARequest struct {
	Password string `json:"password" binding:"required"`
	Code     string `json:"code" binding:"required,len=6"`
}

// Disable2FA disables two-factor authentication
// swagger:route POST /api/v1/profiles/{id}/2fa/disable security disable2FA
//
// Disable two-factor authentication.
//
// Disables 2FA for the account. Requires password and current TOTP code.
//
// Consumes:
//   - application/json
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: disable2FAResponse
//	400: securityErrorResponse
//	401: securityErrorResponse
//	403: securityErrorResponse
//	404: securityErrorResponse
//	500: securityErrorResponse
func (h *Handler) Disable2FA(c *gin.Context) {
	userID, err := parseUintID(c.Param("id"))
	if err != nil {
		response.BadRequestWithCode(c, "INVALID_USER_ID", "invalid user id", nil)
		return
	}

	// Check if the current user is disabling their own 2FA
	currentUserID, exists := middleware.GetUserID(c)
	if !exists || currentUserID != userID {
		response.ForbiddenWithCode(c, "FORBIDDEN", "can only disable 2FA for your own account", nil)
		return
	}

	var req disable2FARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequestWithCode(c, "INVALID_REQUEST", err.Error(), nil)
		return
	}

	// Get user's password hash
	var cred model.UserCredential
	err = h.db.Where("user_id = ? AND provider = ?", userID, "email").First(&cred).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			response.NotFoundWithCode(c, "NO_PASSWORD", "user does not have password authentication", nil)
			return
		}
		response.InternalServerErrorWithCode(c, "DB_ERROR", "failed to load credentials", nil)
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(cred.PasswordHash), []byte(req.Password)); err != nil {
		response.UnauthorizedWithCode(c, "INVALID_PASSWORD", "incorrect password", nil)
		return
	}

	// Get 2FA configuration
	var twoFactor model.UserTwoFactor
	if err := h.db.Where("user_id = ?", userID).First(&twoFactor).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			response.NotFoundWithCode(c, "NOT_ENABLED", "2FA is not enabled", nil)
			return
		}
		response.InternalServerErrorWithCode(c, "DB_ERROR", "failed to load 2FA configuration", nil)
		return
	}

	// Decrypt the secret for verification
	decryptedSecret, err := crypto.Decrypt(twoFactor.Secret)
	if err != nil {
		response.InternalServerErrorWithCode(c, "DECRYPTION_ERROR", "failed to decrypt secret", nil)
		return
	}

	// Verify TOTP code with time window tolerance
	valid, err := totp.ValidateCustom(
		req.Code,
		decryptedSecret,
		time.Now(),
		totp.ValidateOpts{
			Period:    30,
			Skew:      1, // Accept ±1 period (±30 seconds)
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
	)
	valid = err == nil && valid
	if !valid {
		// Try backup codes
		var backupCodes []string
		if err := json.Unmarshal([]byte(twoFactor.BackupCodes), &backupCodes); err == nil {
			codeValid := false
			for _, hashedCode := range backupCodes {
				if err := bcrypt.CompareHashAndPassword([]byte(hashedCode), []byte(req.Code)); err == nil {
					codeValid = true
					break
				}
			}
			if !codeValid {
				response.UnauthorizedWithCode(c, "INVALID_CODE", "invalid verification code", nil)
				return
			}
		} else {
			response.UnauthorizedWithCode(c, "INVALID_CODE", "invalid verification code", nil)
			return
		}
	}

	// Disable 2FA
	err = h.db.Transaction(func(tx *gorm.DB) error {
		// Delete 2FA record
		if err := tx.Delete(&twoFactor).Error; err != nil {
			return err
		}

		// Log the action
		auditLog := model.AuditLog{
			UserID:     userID,
			Action:     "2fa_disabled",
			Resource:   "user_two_factor",
			ResourceID: twoFactor.ID,
			IP:         c.ClientIP(),
			UserAgent:  c.GetHeader("User-Agent"),
			CreatedAt:  time.Now(),
		}

		return tx.Create(&auditLog).Error
	})

	if err != nil {
		response.InternalServerErrorWithCode(c, "DELETE_FAILED", "failed to disable 2FA", nil)
		return
	}

	response.Success(c, gin.H{
		"message": "2FA disabled successfully",
	})
}

// GetDevices returns list of user's login devices
// swagger:route GET /api/v1/profiles/{id}/devices security getDevices
//
// Get login devices with pagination.
//
// Retrieves a paginated list of devices that have been used to access the account.
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: paginatedResponse
//	400: securityErrorResponse
//	403: securityErrorResponse
//	500: securityErrorResponse
func (h *Handler) GetDevices(c *gin.Context) {
	userID, err := parseUintID(c.Param("id"))
	if err != nil {
		response.BadRequestWithCode(c, "INVALID_USER_ID", "invalid user id", nil)
		return
	}

	// Check if the current user is viewing their own devices
	currentUserID, exists := middleware.GetUserID(c)
	if !exists || currentUserID != userID {
		response.ForbiddenWithCode(c, "FORBIDDEN", "can only view your own devices", nil)
		return
	}

	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	// Count total devices
	var total int64
	if err := h.db.Model(&model.UserDevice{}).Where("user_id = ?", userID).Count(&total).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to count devices", nil)
		return
	}

	// Get paginated devices
	var devices []model.UserDevice
	offset := (page - 1) * pageSize

	if err := h.db.Where("user_id = ?", userID).
		Order("last_active_at DESC").
		Limit(pageSize).
		Offset(offset).
		Find(&devices).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to load devices", nil)
		return
	}

	// Get current session to mark current device
	currentToken := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	var currentSession model.UserSession
	h.db.Where("access_token = ?", currentToken).First(&currentSession)

	deviceList := make([]gin.H, 0, len(devices))
	for _, device := range devices {
		isCurrent := false
		if currentSession.ID != 0 && device.DeviceID == generateDeviceID(currentSession.UserAgent, currentSession.ClientIP) {
			isCurrent = true
		}

		deviceList = append(deviceList, gin.H{
			"device_id":      device.DeviceID,
			"device_name":    device.DeviceName,
			"device_type":    device.DeviceType,
			"os":             device.OS,
			"browser":        device.Browser,
			"ip":             device.IP,
			"location":       device.Location,
			"last_active_at": device.LastActiveAt,
			"is_current":     isCurrent,
			"trust_expiry":   shared.NullTimePtr(device.TrustExpiry),
		})
	}

	response.SuccessWithPagination(c, deviceList, total, page, pageSize)
}

// RemoveDevice removes a login device/session
// swagger:route DELETE /api/v1/profiles/{id}/devices/{device_id} security removeDevice
//
// Remove login device.
//
// Removes a device and revokes all associated sessions.
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: removeDeviceResponse
//	400: securityErrorResponse
//	403: securityErrorResponse
//	404: securityErrorResponse
//	500: securityErrorResponse
func (h *Handler) RemoveDevice(c *gin.Context) {
	userID, err := parseUintID(c.Param("id"))
	if err != nil {
		response.BadRequestWithCode(c, "INVALID_USER_ID", "invalid user id", nil)
		return
	}

	deviceID := strings.TrimSpace(c.Param("device_id"))
	if deviceID == "" {
		response.BadRequestWithCode(c, "INVALID_DEVICE_ID", "device id is required", nil)
		return
	}

	// Check if the current user is removing their own device
	currentUserID, exists := middleware.GetUserID(c)
	if !exists || currentUserID != userID {
		response.ForbiddenWithCode(c, "FORBIDDEN", "can only remove your own devices", nil)
		return
	}

	// Check if device exists
	var device model.UserDevice
	err = h.db.Where("user_id = ? AND device_id = ?", userID, deviceID).First(&device).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			response.NotFoundWithCode(c, "DEVICE_NOT_FOUND", "device not found", nil)
			return
		}
		response.InternalServerErrorWithCode(c, "DB_ERROR", "failed to load device", nil)
		return
	}

	// Don't allow removing current device
	currentToken := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	var currentSession model.UserSession
	h.db.Where("access_token = ?", currentToken).First(&currentSession)

	if currentSession.ID != 0 && device.DeviceID == generateDeviceID(currentSession.UserAgent, currentSession.ClientIP) {
		response.ForbiddenWithCode(c, "CURRENT_DEVICE", "cannot remove current device", nil)
		return
	}

	// Remove device and revoke associated sessions
	err = h.db.Transaction(func(tx *gorm.DB) error {
		// Delete device
		if err := tx.Delete(&device).Error; err != nil {
			return err
		}

		// Revoke all sessions from this device
		// In a real implementation, you'd need to track which sessions belong to which device
		// For now, we'll revoke sessions with matching user agent pattern
		if err := tx.Model(&model.UserSession{}).
			Where("user_id = ? AND user_agent LIKE ?", userID, "%"+device.Browser+"%").
			Where("revoked_at IS NULL").
			Update("revoked_at", time.Now()).
			Update("revoked_reason", "device_removed").Error; err != nil {
			return err
		}

		// Log the action
		auditLog := model.AuditLog{
			UserID:     userID,
			Action:     "device_removed",
			Resource:   "user_device",
			ResourceID: device.ID,
			IP:         c.ClientIP(),
			UserAgent:  c.GetHeader("User-Agent"),
			Details:    fmt.Sprintf(`{"removed_device": "%s"}`, device.DeviceName),
			CreatedAt:  time.Now(),
		}

		return tx.Create(&auditLog).Error
	})

	if err != nil {
		response.InternalServerErrorWithCode(c, "DELETE_FAILED", "failed to remove device", nil)
		return
	}

	response.Success(c, gin.H{
		"message": "device removed successfully",
	})
}

func parseUintID(raw string) (uint64, error) {
	return strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
}

// generateDeviceID creates a unique device identifier from user agent and IP
func generateDeviceID(userAgent, clientIP string) string {
	data := userAgent + clientIP
	hash := make([]byte, 16)
	copy(hash, []byte(data))
	return base64.URLEncoding.EncodeToString(hash)[:22]
}

// Helper function to extract device info from user agent
func parseUserAgent(userAgent string) (deviceType, os, browser string) {
	ua := strings.ToLower(userAgent)

	// Detect device type
	if strings.Contains(ua, "mobile") || strings.Contains(ua, "android") || strings.Contains(ua, "iphone") {
		deviceType = "mobile"
	} else if strings.Contains(ua, "tablet") || strings.Contains(ua, "ipad") {
		deviceType = "tablet"
	} else {
		deviceType = "desktop"
	}

	// Detect OS
	switch {
	case strings.Contains(ua, "windows"):
		os = "Windows"
	case strings.Contains(ua, "mac"):
		os = "macOS"
	case strings.Contains(ua, "linux"):
		os = "Linux"
	case strings.Contains(ua, "android"):
		os = "Android"
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		os = "iOS"
	default:
		os = "Unknown"
	}

	// Detect browser
	switch {
	case strings.Contains(ua, "chrome"):
		browser = "Chrome"
	case strings.Contains(ua, "firefox"):
		browser = "Firefox"
	case strings.Contains(ua, "safari"):
		browser = "Safari"
	case strings.Contains(ua, "edge"):
		browser = "Edge"
	case strings.Contains(ua, "opera"):
		browser = "Opera"
	default:
		browser = "Unknown"
	}

	return
}

// store2FASetupData stores temporary 2FA setup data in Redis
func (h *Handler) store2FASetupData(ctx context.Context, key string, data []byte, ttl time.Duration) error {
	if h.sessionCache == nil {
		return fmt.Errorf("session cache not available")
	}
	return h.sessionCache.Set(ctx, key, data, ttl)
}

// get2FASetupData retrieves temporary 2FA setup data from Redis
func (h *Handler) get2FASetupData(ctx context.Context, key string) ([]byte, error) {
	if h.sessionCache == nil {
		return nil, fmt.Errorf("session cache not available")
	}
	return h.sessionCache.Get(ctx, key)
}

// delete2FASetupData removes temporary 2FA setup data from Redis
func (h *Handler) delete2FASetupData(ctx context.Context, key string) error {
	if h.sessionCache == nil {
		return nil
	}
	return h.sessionCache.Delete(ctx, key)
}

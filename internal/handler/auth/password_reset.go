package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"paigram/internal/email"
	"paigram/internal/logging"
	"paigram/internal/model"
	"paigram/internal/response"
)

// ForgotPasswordRequest is the request payload for forgot password
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordRequest is the request payload for reset password
type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=72"`
}

// ForgotPassword initiates password reset flow
// @Summary Request password reset
// @Description Send password reset email to user
// @Tags auth
// @Accept json
// @Produce json
// @Param request body ForgotPasswordRequest true "Forgot password request"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 429 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/auth/forgot-password [post]
func (h *Handler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequestWithCode(c, "INVALID_INPUT", "invalid request", map[string]string{
			"error": err.Error(),
		})
		return
	}

	// Find user by email
	var user model.User
	var userEmail model.UserEmail
	if err := h.db.Where("email = ? AND is_primary = ?", req.Email, true).
		First(&userEmail).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Don't reveal if email exists or not for security
			response.Success(c, gin.H{
				"message": "if the email exists, a password reset link has been sent",
			})
			return
		}
		logging.Error("failed to query user email",
			zap.Error(err),
			zap.String("email", req.Email),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Get the user
	if err := h.db.First(&user, userEmail.UserID).Error; err != nil {
		logging.Error("failed to query user",
			zap.Error(err),
			zap.Uint64("user_id", userEmail.UserID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Check if user account is active
	if user.Status != model.UserStatusActive {
		response.BadRequestWithCode(c, "ACCOUNT_NOT_ACTIVE", "account is not active", nil)
		return
	}

	// Generate password reset token
	token, tokenHash, err := generatePasswordResetToken()
	if err != nil {
		logging.Error("failed to generate reset token",
			zap.Error(err),
			zap.Uint64("user_id", user.ID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Invalidate any existing reset tokens for this user
	if err := h.db.Where("user_id = ? AND used_at IS NULL", user.ID).
		Updates(map[string]interface{}{
			"used_at": time.Now(),
		}).Error; err != nil {
		logging.Error("failed to invalidate existing tokens",
			zap.Error(err),
			zap.Uint64("user_id", user.ID),
		)
		// Continue anyway, not a critical error
	}

	// Save reset token to database
	resetToken := &model.PasswordResetToken{
		UserID:    user.ID,
		Token:     tokenHash,
		ExpiresAt: time.Now().Add(time.Duration(h.cfg.PasswordResetTokenTTLSeconds) * time.Second),
	}

	if err := h.db.Create(resetToken).Error; err != nil {
		logging.Error("failed to create reset token",
			zap.Error(err),
			zap.Uint64("user_id", user.ID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Send password reset email (async)
	emailService, err := email.NewService(h.emailCfg)
	if err != nil {
		logging.Error("failed to create email service",
			zap.Error(err),
		)
		// Continue without sending email
	} else {
		baseURL := c.Request.Header.Get("Origin")
		if baseURL == "" {
			baseURL = fmt.Sprintf("http://%s", c.Request.Host)
		}

		if err := emailService.SendPasswordResetEmail(c.Request.Context(), userEmail.Email, token, baseURL); err != nil {
			logging.Error("failed to send password reset email",
				zap.Error(err),
				zap.Uint64("user_id", user.ID),
			)
			// Continue anyway
		}
	}

	response.Success(c, gin.H{
		"message": "if the email exists, a password reset link has been sent",
	})
}

// ResetPassword resets user password with token
// @Summary Reset password
// @Description Reset user password using reset token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body ResetPasswordRequest true "Reset password request"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/auth/reset-password [post]
func (h *Handler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequestWithCode(c, "INVALID_INPUT", "invalid request", map[string]string{
			"error": err.Error(),
		})
		return
	}

	// Hash the provided token to match database
	tokenHash := hashToken(req.Token)

	// Find valid reset token
	var resetToken model.PasswordResetToken
	if err := h.db.Where("token = ? AND expires_at > ? AND used_at IS NULL", tokenHash, time.Now()).
		First(&resetToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.BadRequestWithCode(c, "INVALID_TOKEN", "invalid or expired reset token", nil)
			return
		}
		logging.Error("failed to query reset token",
			zap.Error(err),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Get user
	var user model.User
	if err := h.db.First(&user, resetToken.UserID).Error; err != nil {
		logging.Error("failed to query user",
			zap.Error(err),
			zap.Uint64("user_id", resetToken.UserID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		logging.Error("failed to hash password",
			zap.Error(err),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Update password and mark token as used in a transaction
	err = h.db.Transaction(func(tx *gorm.DB) error {
		// Update password
		if err := tx.Model(&user).Update("password_hash", string(hashedPassword)).Error; err != nil {
			return fmt.Errorf("update password: %w", err)
		}

		// Mark token as used
		now := time.Now()
		if err := tx.Model(&resetToken).Update("used_at", sql.NullTime{
			Time:  now,
			Valid: true,
		}).Error; err != nil {
			return fmt.Errorf("mark token as used: %w", err)
		}

		// Revoke all active sessions for security
		if err := h.revokeAllUserSessions(tx, user.ID); err != nil {
			logging.Warn("failed to revoke sessions",
				zap.Error(err),
				zap.Uint64("user_id", user.ID),
			)
			// Continue anyway
		}

		return nil
	})

	if err != nil {
		logging.Error("failed to reset password",
			zap.Error(err),
			zap.Uint64("user_id", user.ID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Send password changed notification email
	emailService, err := email.NewService(h.emailCfg)
	if err != nil {
		logging.Error("failed to create email service",
			zap.Error(err),
		)
		// Continue without sending email
	} else {
		// Get primary email
		var userEmail model.UserEmail
		if err := h.db.Where("user_id = ? AND is_primary = ?", user.ID, true).
			First(&userEmail).Error; err != nil {
			logging.Warn("failed to get user primary email",
				zap.Error(err),
				zap.Uint64("user_id", user.ID),
			)
		} else {
			if err := emailService.SendPasswordChangedEmail(c.Request.Context(), userEmail.Email); err != nil {
				logging.Error("failed to send password changed email",
					zap.Error(err),
					zap.Uint64("user_id", user.ID),
				)
				// Continue anyway
			}
		}
	}

	response.Success(c, gin.H{
		"message": "password has been reset successfully",
	})
}

// generatePasswordResetToken generates a secure random token
// Returns the plain token (to send to user) and the hashed token (to store in DB)
func generatePasswordResetToken() (plain, hashed string, err error) {
	// Generate 32 random bytes
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", fmt.Errorf("generate random bytes: %w", err)
	}

	// Convert to hex string (64 characters)
	plain = hex.EncodeToString(bytes)

	// Hash for storage
	hashed = hashToken(plain)

	return plain, hashed, nil
}

// hashToken is now defined in helpers.go (SHA-256 implementation)

// revokeAllUserSessions revokes all active sessions for a user
func (h *Handler) revokeAllUserSessions(tx *gorm.DB, userID uint64) error {
	// Get all active sessions for the user
	var sessions []model.UserSession
	if err := tx.Where("user_id = ?", userID).Find(&sessions).Error; err != nil {
		return fmt.Errorf("query user sessions: %w", err)
	}

	// Note: We cannot remove tokens from cache here because we don't have the original tokens
	// The cache entries will naturally expire based on their TTL
	// The revoked_at flag in the database will prevent any cached tokens from being used

	// Delete all user sessions from database
	if err := tx.Where("user_id = ?", userID).Delete(&model.UserSession{}).Error; err != nil {
		return fmt.Errorf("delete user sessions: %w", err)
	}

	// Delete all user devices
	if err := tx.Where("user_id = ?", userID).Delete(&model.UserDevice{}).Error; err != nil {
		return fmt.Errorf("delete user devices: %w", err)
	}

	return nil
}

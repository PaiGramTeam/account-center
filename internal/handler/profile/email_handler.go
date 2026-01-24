package profile

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/handler/shared"
	"paigram/internal/model"
	"paigram/internal/response"
)

// EmailHandler manages email-related operations for user profiles.
type EmailHandler struct {
	db  *gorm.DB
	cfg config.AuthConfig
}

// NewEmailHandler constructs an email handler.
func NewEmailHandler(db *gorm.DB, cfg config.AuthConfig) *EmailHandler {
	return &EmailHandler{
		db:  db,
		cfg: cfg,
	}
}

// RegisterEmailRoutes binds email management endpoints beneath the given route group.
func (h *EmailHandler) RegisterEmailRoutes(rg *gin.RouterGroup) {
	rg.POST("/:id/emails", h.AddEmail)
	rg.DELETE("/:id/emails/:email", h.DeleteEmail)
	rg.PATCH("/:id/emails/:email/primary", h.SetPrimaryEmail)
	rg.POST("/:id/emails/:email/verify", h.ResendVerificationEmail)
}

type addEmailRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// swagger:route POST /api/v1/profiles/{id}/emails profile addEmail
//
// Add new email address.
//
// Adds a new email address to user profile and sends verification email.
//
// Consumes:
//   - application/json
//
// Produces:
//   - application/json
//
// Responses:
//
//	201: addEmailResponse
//	400: profileErrorResponse
//	404: profileErrorResponse
//	409: profileErrorResponse
//	500: profileErrorResponse
//
// AddEmail adds a new email address to user profile.
func (h *EmailHandler) AddEmail(c *gin.Context) {
	userID, err := parseUintID(c.Param("id"))
	if err != nil {
		response.BadRequestWithCode(c, "INVALID_USER_ID", "invalid user id", nil)
		return
	}

	var req addEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequestWithCode(c, "INVALID_INPUT", err.Error(), nil)
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))

	// Validate email format
	if _, err := mail.ParseAddress(email); err != nil {
		response.BadRequestWithCode(c, "INVALID_EMAIL_FORMAT", "invalid email format", gin.H{
			"field": "email",
		})
		return
	}

	// Check if user exists
	var user model.User
	if err := h.db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFoundWithCode(c, "USER_NOT_FOUND", "user not found", nil)
			return
		}
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "failed to load user", nil)
		return
	}

	// Check if email already exists in system
	var existingEmail model.UserEmail
	if err := h.db.Where("email = ?", email).First(&existingEmail).Error; err == nil {
		if existingEmail.UserID == userID {
			response.ConflictWithCode(c, "EMAIL_ALREADY_ADDED", "email already added to this account", nil)
		} else {
			response.ConflictWithCode(c, "EMAIL_IN_USE", "email already in use by another account", nil)
		}
		return
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "failed to check email uniqueness", nil)
		return
	}

	// Generate verification token
	verificationToken, err := generateVerificationToken()
	if err != nil {
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "failed to generate verification token", nil)
		return
	}

	verificationTTL := time.Duration(h.cfg.EmailVerificationTTLSeconds) * time.Second
	if verificationTTL <= 0 {
		verificationTTL = 24 * time.Hour
	}
	verificationExpiry := time.Now().UTC().Add(verificationTTL)

	// Create email record
	emailRecord := model.UserEmail{
		UserID:             userID,
		Email:              email,
		IsPrimary:          false, // New emails are never primary by default
		VerificationToken:  verificationToken,
		VerificationExpiry: shared.MakeNullTime(verificationExpiry),
	}

	if err := h.db.Create(&emailRecord).Error; err != nil {
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "failed to add email", nil)
		return
	}

	// TODO: Send verification email via email service
	// emailService.SendVerificationEmail(email, verificationToken)

	response.Created(c, gin.H{
		"email":                   emailRecord.Email,
		"is_primary":              emailRecord.IsPrimary,
		"verified_at":             shared.NullTimePtr(emailRecord.VerifiedAt),
		"verification_token":      verificationToken,
		"verification_expires_at": verificationExpiry.Format(time.RFC3339),
		"message":                 "email added successfully, verification email sent",
	})
}

// swagger:route DELETE /api/v1/profiles/{id}/emails/{email} profile deleteEmail
//
// Delete email address.
//
// Removes an email address from user profile. Cannot delete primary email if it's the only one.
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: deleteEmailResponse
//	400: profileErrorResponse
//	403: profileErrorResponse
//	404: profileErrorResponse
//	500: profileErrorResponse
//
// DeleteEmail removes an email address from user profile.
func (h *EmailHandler) DeleteEmail(c *gin.Context) {
	userID, err := parseUintID(c.Param("id"))
	if err != nil {
		response.BadRequestWithCode(c, "INVALID_USER_ID", "invalid user id", nil)
		return
	}

	email := strings.ToLower(strings.TrimSpace(c.Param("email")))
	if email == "" {
		response.BadRequestWithCode(c, "INVALID_EMAIL", "email is required", nil)
		return
	}

	err = h.db.Transaction(func(tx *gorm.DB) error {
		// Find the email record
		var emailRecord model.UserEmail
		if err := tx.Where("user_id = ? AND email = ?", userID, email).First(&emailRecord).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("email not found: %w", err)
			}
			return fmt.Errorf("failed to load email: %w", err)
		}

		// Count total emails for this user
		var emailCount int64
		if err := tx.Model(&model.UserEmail{}).Where("user_id = ?", userID).Count(&emailCount).Error; err != nil {
			return fmt.Errorf("failed to count emails: %w", err)
		}

		// Cannot delete if it's the only email
		if emailCount <= 1 {
			return fmt.Errorf("cannot delete the only email")
		}

		// If deleting primary email, need to set another as primary first
		if emailRecord.IsPrimary {
			// Find another email to promote
			var anotherEmail model.UserEmail
			if err := tx.Where("user_id = ? AND email != ?", userID, email).First(&anotherEmail).Error; err != nil {
				return fmt.Errorf("failed to find replacement primary email: %w", err)
			}

			// Set the other email as primary
			if err := tx.Model(&model.UserEmail{}).Where("id = ?", anotherEmail.ID).Update("is_primary", true).Error; err != nil {
				return fmt.Errorf("failed to promote new primary email: %w", err)
			}
		}

		// Delete the email record
		if err := tx.Delete(&emailRecord).Error; err != nil {
			return fmt.Errorf("failed to delete email: %w", err)
		}

		return nil
	})

	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "email not found") {
			response.NotFoundWithCode(c, "EMAIL_NOT_FOUND", "email not found", nil)
		} else if strings.Contains(errMsg, "cannot delete the only email") {
			response.ForbiddenWithCode(c, "LAST_EMAIL_CANNOT_DELETE", "cannot delete the only email", nil)
		} else {
			response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "failed to delete email", nil)
		}
		return
	}

	response.Success(c, gin.H{
		"message": "email deleted successfully",
	})
}

// swagger:route PATCH /api/v1/profiles/{id}/emails/{email}/primary profile setPrimaryEmail
//
// Set primary email address.
//
// Sets the specified email as the primary email address for the user.
// The email must be verified before it can be set as primary.
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: setPrimaryEmailResponse
//	400: profileErrorResponse
//	403: profileErrorResponse
//	404: profileErrorResponse
//	500: profileErrorResponse
//
// SetPrimaryEmail sets the specified email as primary.
func (h *EmailHandler) SetPrimaryEmail(c *gin.Context) {
	userID, err := parseUintID(c.Param("id"))
	if err != nil {
		response.BadRequestWithCode(c, "INVALID_USER_ID", "invalid user id", nil)
		return
	}

	email := strings.ToLower(strings.TrimSpace(c.Param("email")))
	if email == "" {
		response.BadRequestWithCode(c, "INVALID_EMAIL", "email is required", nil)
		return
	}

	err = h.db.Transaction(func(tx *gorm.DB) error {
		// Find the email record
		var emailRecord model.UserEmail
		if err := tx.Where("user_id = ? AND email = ?", userID, email).First(&emailRecord).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("email not found: %w", err)
			}
			return fmt.Errorf("failed to load email: %w", err)
		}

		// Check if email is verified
		if !emailRecord.VerifiedAt.Valid {
			return fmt.Errorf("email not verified")
		}

		// Check if already primary
		if emailRecord.IsPrimary {
			return nil // Already primary, nothing to do
		}

		// Unset current primary email
		if err := tx.Model(&model.UserEmail{}).
			Where("user_id = ? AND is_primary = ?", userID, true).
			Update("is_primary", false).Error; err != nil {
			return fmt.Errorf("failed to unset current primary: %w", err)
		}

		// Set new primary email
		if err := tx.Model(&model.UserEmail{}).
			Where("id = ?", emailRecord.ID).
			Update("is_primary", true).Error; err != nil {
			return fmt.Errorf("failed to set primary email: %w", err)
		}

		return nil
	})

	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "email not found") {
			response.NotFoundWithCode(c, "EMAIL_NOT_FOUND", "email not found", nil)
		} else if strings.Contains(errMsg, "email not verified") {
			response.ForbiddenWithCode(c, "EMAIL_NOT_VERIFIED", "email must be verified before setting as primary", nil)
		} else {
			response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "failed to set primary email", nil)
		}
		return
	}

	response.Success(c, gin.H{
		"message": "primary email updated successfully",
	})
}

// swagger:route POST /api/v1/profiles/{id}/emails/{email}/verify profile resendVerificationEmail
//
// Resend email verification.
//
// Resends verification email to the specified email address.
// Generates a new verification token if the previous one expired.
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: resendVerificationResponse
//	400: profileErrorResponse
//	404: profileErrorResponse
//	429: profileErrorResponse
//	500: profileErrorResponse
//
// ResendVerificationEmail resends verification email.
func (h *EmailHandler) ResendVerificationEmail(c *gin.Context) {
	userID, err := parseUintID(c.Param("id"))
	if err != nil {
		response.BadRequestWithCode(c, "INVALID_USER_ID", "invalid user id", nil)
		return
	}

	email := strings.ToLower(strings.TrimSpace(c.Param("email")))
	if email == "" {
		response.BadRequestWithCode(c, "INVALID_EMAIL", "email is required", nil)
		return
	}

	var emailRecord model.UserEmail
	err = h.db.Transaction(func(tx *gorm.DB) error {
		// Find the email record
		if err := tx.Where("user_id = ? AND email = ?", userID, email).First(&emailRecord).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("email not found: %w", err)
			}
			return fmt.Errorf("failed to load email: %w", err)
		}

		// Check if already verified
		if emailRecord.VerifiedAt.Valid {
			return fmt.Errorf("email already verified")
		}

		// Check if recent verification email was sent (rate limiting)
		// Allow resend only if last update was more than 1 minute ago
		if time.Since(emailRecord.UpdatedAt) < time.Minute {
			return fmt.Errorf("rate limited")
		}

		// Generate new verification token
		verificationToken, err := generateVerificationToken()
		if err != nil {
			return fmt.Errorf("failed to generate token: %w", err)
		}

		verificationTTL := time.Duration(h.cfg.EmailVerificationTTLSeconds) * time.Second
		if verificationTTL <= 0 {
			verificationTTL = 24 * time.Hour
		}
		verificationExpiry := time.Now().UTC().Add(verificationTTL)

		// Update email record with new token
		updates := map[string]interface{}{
			"verification_token":  verificationToken,
			"verification_expiry": shared.MakeNullTime(verificationExpiry),
		}
		if err := tx.Model(&model.UserEmail{}).Where("id = ?", emailRecord.ID).Updates(updates).Error; err != nil {
			return fmt.Errorf("failed to update verification token: %w", err)
		}

		// Reload email record with updated values
		if err := tx.First(&emailRecord, emailRecord.ID).Error; err != nil {
			return fmt.Errorf("failed to reload email: %w", err)
		}

		return nil
	})

	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "email not found") {
			response.NotFoundWithCode(c, "EMAIL_NOT_FOUND", "email not found", nil)
		} else if strings.Contains(errMsg, "email already verified") {
			response.BadRequestWithCode(c, "EMAIL_ALREADY_VERIFIED", "email is already verified", nil)
		} else if strings.Contains(errMsg, "rate limited") {
			response.ErrorWithCode(c, 429, "RATE_LIMITED", "please wait before requesting another verification email", gin.H{
				"retry_after_seconds": 60,
			})
		} else {
			response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "failed to resend verification email", nil)
		}
		return
	}

	// TODO: Send verification email via email service
	// emailService.SendVerificationEmail(email, emailRecord.VerificationToken)

	response.Success(c, gin.H{
		"message":                 "verification email sent successfully",
		"verification_expires_at": emailRecord.VerificationExpiry.Time.Format(time.RFC3339),
	})
}

// generateVerificationToken creates a random token for email verification.
func generateVerificationToken() (string, error) {
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

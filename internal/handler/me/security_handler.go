package me

import (
	"context"
	"errors"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"paigram/internal/logging"
	"paigram/internal/middleware"
	"paigram/internal/response"
	serviceme "paigram/internal/service/me"
)

type updatePasswordRequest struct {
	OldPassword         string `json:"old_password" binding:"required"`
	NewPassword         string `json:"new_password" binding:"required,min=8,max=72"`
	RevokeOtherSessions bool   `json:"revoke_other_sessions"`
}

type setupTwoFactorRequest struct {
	Password string `json:"password" binding:"required"`
}

type confirmTwoFactorRequest struct {
	Code string `json:"code" binding:"required,len=6"`
}

type disableTwoFactorRequest struct {
	Password string `json:"password" binding:"required"`
	Code     string `json:"code" binding:"required,len=6"`
}

type regenerateBackupCodesRequest struct {
	Password string `json:"password" binding:"required"`
}

// SecurityReaderWriter describes the security service dependency.
type SecurityReaderWriter interface {
	GetOverview(context.Context, uint64) (*serviceme.SecurityOverview, error)
	UpdatePassword(context.Context, serviceme.UpdatePasswordInput) error
	SetupTwoFactor(context.Context, serviceme.SetupTwoFactorInput) (*serviceme.TwoFactorSetupView, error)
	ConfirmTwoFactor(context.Context, serviceme.ConfirmTwoFactorInput) error
	DisableTwoFactor(context.Context, serviceme.DisableTwoFactorInput) error
	RegenerateBackupCodes(context.Context, serviceme.RegenerateBackupCodesInput) ([]string, error)
}

// SecurityHandler serves /me security endpoints.
type SecurityHandler struct {
	service SecurityReaderWriter
}

// NewSecurityHandler creates a security handler.
func NewSecurityHandler(service SecurityReaderWriter) *SecurityHandler {
	return &SecurityHandler{service: service}
}

// swagger:route GET /api/v1/me/security/overview me getMeSecurityOverview
//
// Get current-user security overview.
//
// Returns a security summary for the authenticated account.
//
// Produces:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//   200: meSecurityOverviewResponse
//   401: meErrorResponse
//   500: meErrorResponse
// GetOverview returns the current-user security summary.
func (h *SecurityHandler) GetOverview(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	overview, err := h.service.GetOverview(c.Request.Context(), userID)
	if err != nil {
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "failed to load security overview", nil)
		return
	}
	response.Success(c, overview)
}

// swagger:route PUT /api/v1/me/security/password me updateMePassword
//
// Update current-user password.
//
// Changes the authenticated user's password.
//
// Produces:
//   - application/json
//
// Consumes:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//   200: meMessageResponse
//   400: meErrorResponse
//   401: meErrorResponse
//   404: meErrorResponse
//   500: meErrorResponse
// UpdatePassword changes the current-user password.
func (h *SecurityHandler) UpdatePassword(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	var req updatePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logging.Error("update password: invalid request body", zap.Error(err), zap.Uint64("user_id", userID))
		response.BadRequestWithCode(c, response.ErrCodeInvalidInput, "invalid request body", nil)
		return
	}
	err := h.service.UpdatePassword(c.Request.Context(), serviceme.UpdatePasswordInput{UserID: userID, OldPassword: req.OldPassword, NewPassword: req.NewPassword, RevokeOtherSessions: req.RevokeOtherSessions, CurrentAccessToken: bearerToken(c.GetHeader("Authorization")), ClientIP: c.ClientIP(), UserAgent: c.GetHeader("User-Agent")})
	if err != nil {
		h.writeSecurityError(c, err, "failed to update password")
		return
	}
	response.Success(c, gin.H{"message": "password changed successfully"})
}

// swagger:route POST /api/v1/me/security/2fa/setup me setupMeTwoFactor
//
// Start current-user 2FA setup.
//
// Generates a TOTP secret and backup codes for the authenticated account.
//
// Produces:
//   - application/json
//
// Consumes:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//   200: meTwoFactorSetupResponse
//   400: meErrorResponse
//   401: meErrorResponse
//   404: meErrorResponse
//   409: meErrorResponse
//   500: meErrorResponse
// SetupTwoFactor prepares 2FA setup for the current user.
func (h *SecurityHandler) SetupTwoFactor(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	var req setupTwoFactorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logging.Error("setup 2FA: invalid request body", zap.Error(err), zap.Uint64("user_id", userID))
		response.BadRequestWithCode(c, response.ErrCodeInvalidInput, "invalid request body", nil)
		return
	}
	setup, err := h.service.SetupTwoFactor(c.Request.Context(), serviceme.SetupTwoFactorInput{UserID: userID, Password: req.Password})
	if err != nil {
		h.writeSecurityError(c, err, "failed to setup 2FA")
		return
	}
	response.Success(c, setup)
}

// swagger:route POST /api/v1/me/security/2fa/confirm me confirmMeTwoFactor
//
// Confirm current-user 2FA.
//
// Activates a pending TOTP configuration for the authenticated account.
//
// Produces:
//   - application/json
//
// Consumes:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//   200: meMessageResponse
//   400: meErrorResponse
//   401: meErrorResponse
//   500: meErrorResponse
// ConfirmTwoFactor activates a prepared 2FA setup.
func (h *SecurityHandler) ConfirmTwoFactor(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	var req confirmTwoFactorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logging.Error("confirm 2FA: invalid request body", zap.Error(err), zap.Uint64("user_id", userID))
		response.BadRequestWithCode(c, response.ErrCodeInvalidInput, "invalid request body", nil)
		return
	}
	err := h.service.ConfirmTwoFactor(c.Request.Context(), serviceme.ConfirmTwoFactorInput{UserID: userID, Code: req.Code, ClientIP: c.ClientIP(), UserAgent: c.GetHeader("User-Agent")})
	if err != nil {
		h.writeSecurityError(c, err, "failed to confirm 2FA")
		return
	}
	response.Success(c, gin.H{"message": "2FA enabled successfully"})
}

// swagger:route DELETE /api/v1/me/security/2fa me disableMeTwoFactor
//
// Disable current-user 2FA.
//
// Removes two-factor authentication from the authenticated account.
//
// Produces:
//   - application/json
//
// Consumes:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//   200: meMessageResponse
//   400: meErrorResponse
//   401: meErrorResponse
//   404: meErrorResponse
//   500: meErrorResponse
// DisableTwoFactor disables 2FA for the current user.
func (h *SecurityHandler) DisableTwoFactor(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	var req disableTwoFactorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logging.Error("disable 2FA: invalid request body", zap.Error(err), zap.Uint64("user_id", userID))
		response.BadRequestWithCode(c, response.ErrCodeInvalidInput, "invalid request body", nil)
		return
	}
	err := h.service.DisableTwoFactor(c.Request.Context(), serviceme.DisableTwoFactorInput{UserID: userID, Password: req.Password, Code: req.Code, ClientIP: c.ClientIP(), UserAgent: c.GetHeader("User-Agent")})
	if err != nil {
		h.writeSecurityError(c, err, "failed to disable 2FA")
		return
	}
	response.Success(c, gin.H{"message": "2FA disabled successfully"})
}

// swagger:route POST /api/v1/me/security/2fa/backup-codes/regenerate me regenerateMeBackupCodes
//
// Regenerate current-user backup codes.
//
// Replaces the authenticated user's stored 2FA backup codes.
//
// Produces:
//   - application/json
//
// Consumes:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//   200: meBackupCodesResponse
//   400: meErrorResponse
//   401: meErrorResponse
//   404: meErrorResponse
//   500: meErrorResponse
// RegenerateBackupCodes rotates stored 2FA backup codes.
func (h *SecurityHandler) RegenerateBackupCodes(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	var req regenerateBackupCodesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logging.Error("regenerate backup codes: invalid request body", zap.Error(err), zap.Uint64("user_id", userID))
		response.BadRequestWithCode(c, response.ErrCodeInvalidInput, "invalid request body", nil)
		return
	}
	backupCodes, err := h.service.RegenerateBackupCodes(c.Request.Context(), serviceme.RegenerateBackupCodesInput{UserID: userID, Password: req.Password, ClientIP: c.ClientIP(), UserAgent: c.GetHeader("User-Agent")})
	if err != nil {
		h.writeSecurityError(c, err, "failed to regenerate backup codes")
		return
	}
	response.Success(c, gin.H{"message": "backup codes regenerated successfully", "backup_codes": backupCodes})
}

// writeSecurityError maps service-layer sentinels onto HTTP responses. The
// user-facing message strings are written as literals here (rather than via
// err.Error()) so that the prose surfaced to clients is auditable in the
// handler — V13 forbids piping err.Error() into response bodies because gorm
// or driver errors could otherwise leak through unexpected error paths.
func (h *SecurityHandler) writeSecurityError(c *gin.Context, err error, fallback string) {
	switch {
	case errors.Is(err, serviceme.ErrNoPasswordLogin):
		response.NotFoundWithCode(c, "NO_PASSWORD", "user does not have password authentication", nil)
	case errors.Is(err, serviceme.ErrInvalidPassword):
		response.UnauthorizedWithCode(c, "INVALID_CREDENTIAL", "incorrect password", nil)
	case errors.Is(err, serviceme.ErrInvalidTwoFactorCode):
		response.UnauthorizedWithCode(c, "INVALID_CREDENTIAL", "invalid verification code", nil)
	case errors.Is(err, serviceme.ErrTwoFactorAlreadyEnabled):
		response.ConflictWithCode(c, "ALREADY_ENABLED", "2FA is already enabled", nil)
	case errors.Is(err, serviceme.ErrTwoFactorNotEnabled):
		response.NotFoundWithCode(c, "2FA_NOT_ENABLED", "2FA is not enabled", nil)
	case errors.Is(err, serviceme.ErrTwoFactorSetupExpired):
		response.BadRequestWithCode(c, "SETUP_EXPIRED", "2FA setup expired or not found", nil)
	default:
		logging.Error("security operation failed", zap.Error(err), zap.String("fallback", fallback))
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", fallback, nil)
	}
}

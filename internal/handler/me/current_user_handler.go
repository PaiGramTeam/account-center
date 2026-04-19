package me

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/middleware"
	"paigram/internal/response"
	serviceme "paigram/internal/service/me"
)

// CurrentUserReader describes the current-user service dependency.
type CurrentUserReader interface {
	GetCurrentUserView(context.Context, uint64) (*serviceme.CurrentUserView, error)
	GetDashboardSummary(context.Context, uint64) (*serviceme.DashboardSummaryView, error)
	ListEmails(context.Context, uint64) ([]serviceme.EmailView, error)
	CreateEmail(context.Context, serviceme.CreateEmailInput) (*serviceme.CreatedEmailView, error)
	DeleteEmail(context.Context, uint64, uint64) error
	VerifyEmail(context.Context, serviceme.VerifyEmailInput) (*serviceme.VerificationEmailView, error)
	PatchPrimaryEmail(context.Context, uint64, uint64) error
	ListLoginMethods(context.Context, uint64) ([]serviceme.LoginMethodView, error)
	DeleteLoginMethod(context.Context, uint64, string) error
}

type createEmailRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type CurrentUserView = serviceme.CurrentUserView

// CurrentUserHandler serves the /me identity surface.
type CurrentUserHandler struct {
	service CurrentUserReader
}

// NewCurrentUserHandler creates a current-user handler.
func NewCurrentUserHandler(service CurrentUserReader) *CurrentUserHandler {
	return &CurrentUserHandler{service: service}
}

// swagger:route GET /api/v1/me me getMe
//
// Get current user.
//
// Returns the authenticated user's self-service profile view, including emails and login methods.
//
// Produces:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//	200: meCurrentUserResponse
//	401: meErrorResponse
//	404: meErrorResponse
//	500: meErrorResponse
//
// GetMe returns the authenticated current-user view.
func (h *CurrentUserHandler) GetMe(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	view, err := h.service.GetCurrentUserView(c.Request.Context(), userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFound(c, "user not found")
			return
		}
		response.InternalServerError(c, "failed to load current user")
		return
	}
	response.Success(c, view)
}

// swagger:route GET /api/v1/me/dashboard-summary me getMeDashboardSummary
//
// Get current-user dashboard summary.
//
// Returns the authenticated user's aggregated dashboard counts for bindings, profiles, and enabled consumers.
//
// Produces:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//	200: meDashboardSummaryResponse
//	401: meErrorResponse
//	500: meErrorResponse
//
// GetDashboardSummary returns the authenticated current-user dashboard aggregate.
func (h *CurrentUserHandler) GetDashboardSummary(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	summary, err := h.service.GetDashboardSummary(c.Request.Context(), userID)
	if err != nil {
		response.InternalServerError(c, "failed to load dashboard summary")
		return
	}
	response.Success(c, summary)
}

// swagger:route GET /api/v1/me/emails me listMeEmails
//
// List current-user emails.
//
// Returns all email addresses attached to the authenticated account.
//
// Produces:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//	200: meEmailsResponse
//	401: meErrorResponse
//	500: meErrorResponse
//
// ListEmails returns the authenticated user's emails.
func (h *CurrentUserHandler) ListEmails(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	emails, err := h.service.ListEmails(c.Request.Context(), userID)
	if err != nil {
		response.InternalServerError(c, "failed to load emails")
		return
	}
	response.Success(c, emails)
}

// swagger:route POST /api/v1/me/emails me createMeEmail
//
// Create current-user email.
//
// Adds an alternate email address to the authenticated user's account and issues a verification token.
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
//	201: meCreatedEmailResponse
//	400: meErrorResponse
//	401: meErrorResponse
//	409: meErrorResponse
//
// CreateEmail adds an alternate email for the authenticated user.
func (h *CurrentUserHandler) CreateEmail(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	var req createEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidInput, err.Error(), nil)
		return
	}
	created, err := h.service.CreateEmail(c.Request.Context(), serviceme.CreateEmailInput{UserID: userID, Email: req.Email, VerificationTTL: 24 * time.Hour})
	if err != nil {
		switch {
		case errors.Is(err, serviceme.ErrEmailAlreadyAddedToAccount):
			response.ConflictWithCode(c, "EMAIL_ALREADY_ADDED", err.Error(), nil)
		case errors.Is(err, serviceme.ErrEmailAlreadyInUse):
			response.ConflictWithCode(c, "EMAIL_IN_USE", err.Error(), nil)
		default:
			response.BadRequestWithCode(c, response.ErrCodeInvalidInput, err.Error(), nil)
		}
		return
	}
	response.Created(c, created)
}

// swagger:route PATCH /api/v1/me/emails/{emailId}/primary me patchMePrimaryEmail
//
// Set primary email.
//
// Promotes a verified email on the authenticated account to primary.
//
// Produces:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//	200: meMessageResponse
//	400: meErrorResponse
//	401: meErrorResponse
//	403: meErrorResponse
//	404: meErrorResponse
//	500: meErrorResponse
//
// PatchPrimaryEmail promotes a verified email to primary.
func (h *CurrentUserHandler) PatchPrimaryEmail(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	emailID, err := strconv.ParseUint(c.Param("emailId"), 10, 64)
	if err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidInput, "invalid email id", nil)
		return
	}
	if err := h.service.PatchPrimaryEmail(c.Request.Context(), userID, emailID); err != nil {
		switch {
		case errors.Is(err, serviceme.ErrEmailNotFound):
			response.NotFoundWithCode(c, "EMAIL_NOT_FOUND", err.Error(), nil)
		case errors.Is(err, serviceme.ErrEmailNotVerified):
			response.ForbiddenWithCode(c, "EMAIL_NOT_VERIFIED", err.Error(), nil)
		default:
			response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "failed to set primary email", nil)
		}
		return
	}
	response.Success(c, gin.H{"message": "primary email updated successfully"})
}

// swagger:route DELETE /api/v1/me/emails/{emailId} me deleteMeEmail
//
// Delete current-user email.
//
// Removes an email address from the authenticated account.
//
// Produces:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//	200: meMessageResponse
//	400: meErrorResponse
//	401: meErrorResponse
//	403: meErrorResponse
//	404: meErrorResponse
//	500: meErrorResponse
//
// DeleteEmail removes an existing current-user email.
func (h *CurrentUserHandler) DeleteEmail(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	emailID, err := strconv.ParseUint(c.Param("emailId"), 10, 64)
	if err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidInput, "invalid email id", nil)
		return
	}
	if err := h.service.DeleteEmail(c.Request.Context(), userID, emailID); err != nil {
		switch {
		case errors.Is(err, serviceme.ErrEmailNotFound):
			response.NotFoundWithCode(c, "EMAIL_NOT_FOUND", err.Error(), nil)
		case errors.Is(err, serviceme.ErrLastEmailCannotDelete):
			response.ForbiddenWithCode(c, "LAST_EMAIL_CANNOT_DELETE", err.Error(), nil)
		default:
			response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "failed to delete email", nil)
		}
		return
	}
	response.Success(c, gin.H{"message": "email deleted successfully"})
}

// swagger:route POST /api/v1/me/emails/{emailId}/verify me verifyMeEmail
//
// Resend email verification.
//
// Reissues a verification token for an unverified email on the authenticated account.
//
// Produces:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//	200: meVerifyEmailResponse
//	400: meErrorResponse
//	401: meErrorResponse
//	404: meErrorResponse
//	500: meErrorResponse
//
// VerifyEmail resends verification for an unverified current-user email.
func (h *CurrentUserHandler) VerifyEmail(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	emailID, err := strconv.ParseUint(c.Param("emailId"), 10, 64)
	if err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidInput, "invalid email id", nil)
		return
	}
	view, err := h.service.VerifyEmail(c.Request.Context(), serviceme.VerifyEmailInput{UserID: userID, EmailID: emailID, VerificationTTL: 24 * time.Hour})
	if err != nil {
		switch {
		case errors.Is(err, serviceme.ErrEmailNotFound):
			response.NotFoundWithCode(c, "EMAIL_NOT_FOUND", err.Error(), nil)
		case errors.Is(err, serviceme.ErrEmailAlreadyVerified), errors.Is(err, serviceme.ErrEmailRateLimited):
			response.BadRequestWithCode(c, response.ErrCodeInvalidInput, err.Error(), nil)
		default:
			response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "failed to resend verification email", nil)
		}
		return
	}
	response.Success(c, gin.H{"message": "verification email sent successfully", "verification_expires_at": view.VerificationExpiresAt})
}

// swagger:route GET /api/v1/me/login-methods me listMeLoginMethods
//
// List current-user login methods.
//
// Returns all login methods currently bound to the authenticated account.
//
// Produces:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//	200: meLoginMethodsResponse
//	401: meErrorResponse
//	500: meErrorResponse
//
// ListLoginMethods returns the authenticated user's login methods.
func (h *CurrentUserHandler) ListLoginMethods(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	methods, err := h.service.ListLoginMethods(c.Request.Context(), userID)
	if err != nil {
		response.InternalServerError(c, "failed to load login methods")
		return
	}
	response.Success(c, methods)
}

// swagger:route DELETE /api/v1/me/login-methods/{provider} me deleteMeLoginMethod
//
// Remove current-user login method.
//
// Unbinds a login method from the authenticated account.
//
// Produces:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//	200: meMessageResponse
//	401: meErrorResponse
//	403: meErrorResponse
//	404: meErrorResponse
//	500: meErrorResponse
//
// DeleteLoginMethod unbinds a login method for the authenticated user.
func (h *CurrentUserHandler) DeleteLoginMethod(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	if err := h.service.DeleteLoginMethod(c.Request.Context(), userID, c.Param("provider")); err != nil {
		switch {
		case errors.Is(err, serviceme.ErrProviderNotBound):
			response.NotFoundWithCode(c, "PROVIDER_NOT_BOUND", err.Error(), nil)
		case errors.Is(err, serviceme.ErrCannotRemoveLastLoginMethod), errors.Is(err, serviceme.ErrCannotUnbindPrimaryLogin):
			response.ForbiddenWithCode(c, "FORBIDDEN", err.Error(), nil)
		default:
			response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "failed to delete login method", nil)
		}
		return
	}
	response.Success(c, gin.H{"message": "login method removed successfully"})
}

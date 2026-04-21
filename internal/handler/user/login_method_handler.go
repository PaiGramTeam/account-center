package user

import (
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/response"
	serviceme "paigram/internal/service/me"
)

// swagger:route GET /api/v1/admin/users/{id}/login-methods users listUserLoginMethods
//
// List user login methods.
//
// Returns all login methods currently bound to the target user account.
//
// Produces:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//	200: userLoginMethodsResponse
//	400: errorResponse
//	404: errorResponse
//	500: errorResponse
func (h *Handler) ListUserLoginMethods(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}
	methods, err := h.loginMethods.ListLoginMethods(c.Request.Context(), userID)
	if err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			response.NotFound(c, "user not found")
		default:
			response.InternalServerError(c, "failed to load login methods")
		}
		return
	}
	response.Success(c, methods)
}

// swagger:route PATCH /api/v1/admin/users/{id}/login-methods/{provider}/primary users patchUserPrimaryLoginMethod
//
// Set user primary login method.
//
// Promotes a bound login method on the target user account to primary.
//
// Produces:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//	200: userMessageResponse
//	400: errorResponse
//	404: errorResponse
//	500: errorResponse
func (h *Handler) PatchUserPrimaryLoginMethod(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid user id")
		return
	}
	if err := h.loginMethods.SetPrimaryLoginMethod(c.Request.Context(), userID, c.Param("provider")); err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			response.NotFound(c, "user not found")
		case errors.Is(err, serviceme.ErrProviderNotBound):
			response.NotFound(c, err.Error())
		default:
			response.InternalServerError(c, "failed to set primary login method")
		}
		return
	}
	response.Success(c, gin.H{"message": "primary login method updated successfully"})
}

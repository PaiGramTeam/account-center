package middleware

import (
	"errors"

	"github.com/gin-gonic/gin"

	"paigram/internal/response"
	"paigram/internal/service"
	serviceuser "paigram/internal/service/user"
)

// Require2FA middleware ensures that the user has 2FA enabled
// This middleware should be used after AuthMiddleware
func Require2FA() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from context (set by AuthMiddleware)
		userID, exists := GetUserID(c)
		if !exists {
			response.UnauthorizedWithCode(c, "UNAUTHORIZED", "user not authenticated", nil)
			c.Abort()
			return
		}

		// Check if user has 2FA enabled
		middlewareService := &service.ServiceGroupApp.UserServiceGroup.MiddlewareService
		_, err := middlewareService.GetTwoFactorSecret(userID)

		if err != nil {
			if errors.Is(err, serviceuser.ErrTwoFactorNotEnabled) {
				response.ForbiddenWithCode(c, "2FA_REQUIRED", "two-factor authentication is required for this operation", map[string]string{
					"message": "please enable 2FA to access this resource",
				})
				c.Abort()
				return
			}

			response.InternalServerErrorWithCode(c, "2FA_CHECK_FAILED", "failed to verify two-factor authentication state", nil)
			c.Abort()
			return
		}

		// 2FA is enabled, continue
		c.Set("has_2fa", true)
		// Note: 2fa_id is not set anymore as we don't have the record ID from MiddlewareService
		c.Next()
	}
}

// Optional2FA middleware checks if the user has 2FA enabled and sets a flag in context
// It does not abort the request if 2FA is not enabled
func Optional2FA() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from context (set by AuthMiddleware)
		userID, exists := GetUserID(c)
		if !exists {
			c.Next()
			return
		}

		// Check if user has 2FA enabled
		middlewareService := &service.ServiceGroupApp.UserServiceGroup.MiddlewareService
		_, err := middlewareService.GetTwoFactorSecret(userID)

		if err == nil {
			c.Set("has_2fa", true)
			// Note: 2fa_id is not set anymore as we don't have the record ID from MiddlewareService
		} else if errors.Is(err, serviceuser.ErrTwoFactorNotEnabled) {
			c.Set("has_2fa", false)
		} else {
			response.InternalServerErrorWithCode(c, "2FA_CHECK_FAILED", "failed to verify two-factor authentication state", nil)
			c.Abort()
			return
		}

		c.Next()
	}
}

// Has2FA checks if the user has 2FA enabled from context
func Has2FA(c *gin.Context) bool {
	has2FA, exists := c.Get("has_2fa")
	if !exists {
		return false
	}

	enabled, ok := has2FA.(bool)
	return ok && enabled
}

// Get2FAID retrieves the 2FA record ID from context
func Get2FAID(c *gin.Context) (uint64, bool) {
	twoFactorID, exists := c.Get("2fa_id")
	if !exists {
		return 0, false
	}

	id, ok := twoFactorID.(uint64)
	return id, ok
}

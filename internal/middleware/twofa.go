package middleware

import (
	"errors"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/model"
	"paigram/internal/response"
)

// Require2FA middleware ensures that the user has 2FA enabled
// This middleware should be used after AuthMiddleware
func Require2FA(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from context (set by AuthMiddleware)
		userID, exists := GetUserID(c)
		if !exists {
			response.UnauthorizedWithCode(c, "UNAUTHORIZED", "user not authenticated", nil)
			c.Abort()
			return
		}

		// Check if user has 2FA enabled
		var twoFactor model.UserTwoFactor
		err := db.Where("user_id = ?", userID).First(&twoFactor).Error

		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				response.ForbiddenWithCode(c, "2FA_REQUIRED", "two-factor authentication is required for this operation", map[string]string{
					"message": "please enable 2FA to access this resource",
				})
			} else {
				response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "failed to verify 2FA status", nil)
			}
			c.Abort()
			return
		}

		// 2FA is enabled, continue
		c.Set("has_2fa", true)
		c.Set("2fa_id", twoFactor.ID)
		c.Next()
	}
}

// Optional2FA middleware checks if the user has 2FA enabled and sets a flag in context
// It does not abort the request if 2FA is not enabled
func Optional2FA(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from context (set by AuthMiddleware)
		userID, exists := GetUserID(c)
		if !exists {
			c.Next()
			return
		}

		// Check if user has 2FA enabled
		var twoFactor model.UserTwoFactor
		err := db.Where("user_id = ?", userID).First(&twoFactor).Error

		if err == nil {
			c.Set("has_2fa", true)
			c.Set("2fa_id", twoFactor.ID)
		} else {
			c.Set("has_2fa", false)
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

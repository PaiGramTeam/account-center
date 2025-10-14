package profile

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/handler/shared"
	"paigram/internal/model"
)

// Handler manages profile-related endpoints.
type Handler struct {
	db *gorm.DB
}

// NewHandler constructs a profile handler.
func NewHandler(db *gorm.DB) *Handler {
	return &Handler{db: db}
}

// RegisterRoutes binds profile endpoints beneath the given route group.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.GET("/:id", h.GetProfile)
	rg.PATCH("/:id", h.UpdateProfile)
}

// GetProfile returns profile + email overview for a user.
func (h *Handler) GetProfile(c *gin.Context) {
	userID, err := parseUintID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	var user model.User
	if err := h.db.Preload("Profile").Preload("Emails").First(&user, userID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load profile"})
		return
	}

	primaryEmail := ""
	emails := make([]gin.H, 0, len(user.Emails))
	for _, email := range user.Emails {
		if email.IsPrimary {
			primaryEmail = email.Email
		}
		emails = append(emails, gin.H{
			"email":       email.Email,
			"is_primary":  email.IsPrimary,
			"verified_at": shared.NullTimePtr(email.VerifiedAt),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"user_id":       user.ID,
			"display_name":  user.Profile.DisplayName,
			"avatar_url":    user.Profile.AvatarURL,
			"bio":           user.Profile.Bio,
			"locale":        user.Profile.Locale,
			"status":        user.Status,
			"primary_email": primaryEmail,
			"emails":        emails,
			"last_login_at": shared.NullTimePtr(user.LastLoginAt),
			"created_at":    user.CreatedAt,
			"updated_at":    user.UpdatedAt,
		},
	})
}

type updateProfileRequest struct {
	DisplayName *string `json:"display_name"`
	AvatarURL   *string `json:"avatar_url"`
	Bio         *string `json:"bio"`
	Locale      *string `json:"locale"`
}

// UpdateProfile modifies profile fields.
func (h *Handler) UpdateProfile(c *gin.Context) {
	userID, err := parseUintID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	var req updateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var profile model.UserProfile
	if err := h.db.Where("user_id = ?", userID).First(&profile).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load profile"})
		return
	}

	updates := map[string]interface{}{}
	if req.DisplayName != nil {
		updates["display_name"] = strings.TrimSpace(*req.DisplayName)
	}
	if req.AvatarURL != nil {
		updates["avatar_url"] = strings.TrimSpace(*req.AvatarURL)
	}
	if req.Bio != nil {
		updates["bio"] = strings.TrimSpace(*req.Bio)
	}
	if req.Locale != nil {
		updates["locale"] = strings.TrimSpace(*req.Locale)
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	if err := h.db.Model(&model.UserProfile{}).Where("id = ?", profile.ID).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update profile"})
		return
	}

	if err := h.db.Where("id = ?", profile.ID).First(&profile).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reload profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"user_id":      profile.UserID,
			"display_name": profile.DisplayName,
			"avatar_url":   profile.AvatarURL,
			"bio":          profile.Bio,
			"locale":       profile.Locale,
		},
	})
}

func parseUintID(raw string) (uint64, error) {
	return strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
}

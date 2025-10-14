package user

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/handler/shared"
	"paigram/internal/model"
)

// Handler exposes REST handlers for user resources.
type Handler struct {
	db *gorm.DB
}

// NewHandler constructs a handler with the provided database.
func NewHandler(db *gorm.DB) *Handler {
	return &Handler{db: db}
}

// RegisterRoutes binds user routes to the router group.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.GET("", h.ListUsers)
	rg.GET("/:id", h.GetUser)
}

// swagger:route GET /api/v1/users users listUsers
//
// 列出所有用户及其基础信息。
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: userListResponse
//	500: errorResponse
//
// ListUsers returns all users with basic profile metadata.
func (h *Handler) ListUsers(c *gin.Context) {
	var users []model.User
	if err := h.db.Preload("Profile").Preload("Emails").Order("id DESC").Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to list users"})
		return
	}

	results := make([]UserListItem, 0, len(users))
	for _, user := range users {
		results = append(results, UserListItem{
			ID:               user.ID,
			Status:           user.Status,
			PrimaryLoginType: user.PrimaryLoginType,
			DisplayName:      user.Profile.DisplayName,
			PrimaryEmail:     primaryEmail(user.Emails),
			LastLoginAt:      shared.NullTimePtr(user.LastLoginAt),
			CreatedAt:        user.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, UserListResponse{Data: results})
}

// swagger:route GET /api/v1/users/{id} users getUser
//
// 查看指定用户的详细信息。
//
// Produces:
//   - application/json
//
// Responses:
//
//	200: userDetailResponse
//	400: errorResponse
//	404: errorResponse
//	500: errorResponse
//
// GetUser retrieves full details for a user by id.
func (h *Handler) GetUser(c *gin.Context) {
	id, err := strconv.ParseUint(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid user id"})
		return
	}

	var user model.User
	if err := h.db.Preload("Profile").Preload("Emails").Preload("Sessions").First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to load user"})
		return
	}

	emails := make([]UserEmailPayload, 0, len(user.Emails))
	for _, email := range user.Emails {
		emails = append(emails, UserEmailPayload{
			Email:      email.Email,
			IsPrimary:  email.IsPrimary,
			VerifiedAt: shared.NullTimePtr(email.VerifiedAt),
		})
	}

	c.JSON(http.StatusOK, UserDetailResponse{
		Data: UserDetail{
			ID:               user.ID,
			Status:           user.Status,
			PrimaryLoginType: user.PrimaryLoginType,
			DisplayName:      user.Profile.DisplayName,
			AvatarURL:        user.Profile.AvatarURL,
			Bio:              user.Profile.Bio,
			Locale:           user.Profile.Locale,
			PrimaryEmail:     primaryEmail(user.Emails),
			Emails:           emails,
			LastLoginAt:      shared.NullTimePtr(user.LastLoginAt),
			CreatedAt:        user.CreatedAt,
			UpdatedAt:        user.UpdatedAt,
		},
	})
}

func primaryEmail(emails []model.UserEmail) string {
	for _, email := range emails {
		if email.IsPrimary {
			return email.Email
		}
	}
	if len(emails) > 0 {
		return emails[0].Email
	}
	return ""
}

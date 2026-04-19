package userrole

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/model"
	"paigram/internal/response"
)

// Handler manages user role assignment HTTP requests.
type Handler struct {
	db *gorm.DB
}

// NewHandler creates a new user role handler.
func NewHandler(db *gorm.DB) *Handler {
	return &Handler{
		db: db,
	}
}

// RegisterRoutes registers user role management routes.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.GET("/:id/roles", h.GetUserRoles)
	rg.GET("/:id/permissions", h.GetUserPermissions)
}

// GetUserRoles returns all roles assigned to a user.
// @Summary Get user roles
// @Tags user-roles
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {array} model.Role
// @Failure 400 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/admin/users/{id}/roles [get]
func (h *Handler) GetUserRoles(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid user ID")
		return
	}

	var userRoles []model.UserRole
	if err := h.db.Where("user_id = ?", userID).Preload("Role").Find(&userRoles).Error; err != nil {
		response.InternalServerError(c, "failed to get user roles")
		return
	}

	// Extract roles from UserRole associations
	roles := make([]model.Role, 0, len(userRoles))
	for _, ur := range userRoles {
		roles = append(roles, ur.Role)
	}

	response.Success(c, roles)
}

// GetUserPermissions returns all permissions for a user.
// @Summary Get user permissions
// @Tags user-roles
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {array} model.Permission
// @Failure 400 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/admin/users/{id}/permissions [get]
func (h *Handler) GetUserPermissions(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid user ID")
		return
	}

	// Get permissions through user roles
	var permissions []model.Permission
	err = h.db.Distinct().
		Model(&model.Permission{}).
		Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
		Joins("JOIN user_roles ON user_roles.role_id = role_permissions.role_id").
		Where("user_roles.user_id = ?", userID).
		Find(&permissions).Error

	if err != nil {
		response.InternalServerError(c, "failed to get user permissions")
		return
	}

	response.Success(c, permissions)
}

package userrole

import (
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/middleware"
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
	rg.POST("/:id/roles", h.AssignRoleToUser)
	rg.DELETE("/:id/roles/:roleId", h.RemoveRoleFromUser)
	rg.GET("/:id/permissions", h.GetUserPermissions)
}

// AssignRoleRequest represents the request body for assigning a role to a user.
type AssignRoleRequest struct {
	RoleID uint64 `json:"role_id" binding:"required"`
}

// GetUserRoles returns all roles assigned to a user.
// @Summary Get user roles
// @Tags user-roles
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {array} model.Role
// @Failure 400 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/users/{id}/roles [get]
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
// @Router /api/v1/users/{id}/permissions [get]
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

// AssignRoleToUser assigns a role to a user.
// @Summary Assign role to user
// @Tags user-roles
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Param body body AssignRoleRequest true "Role ID"
// @Success 200 {object} gin.H
// @Failure 400 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/users/{id}/roles [post]
func (h *Handler) AssignRoleToUser(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid user ID")
		return
	}

	var req AssignRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	// Get current user ID from context
	currentUserID, _ := middleware.GetUserID(c)

	// Check if role exists
	var role model.Role
	if err := h.db.First(&role, req.RoleID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFound(c, "role not found")
			return
		}
		response.InternalServerError(c, "failed to get role")
		return
	}

	// Check if user already has this role
	var existingUserRole model.UserRole
	err = h.db.Where("user_id = ? AND role_id = ?", userID, req.RoleID).First(&existingUserRole).Error
	if err == nil {
		response.BadRequest(c, "user already has this role")
		return
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		response.InternalServerError(c, "failed to check existing role")
		return
	}

	// Create user role assignment
	userRole := model.UserRole{
		UserID:    userID,
		RoleID:    req.RoleID,
		GrantedBy: currentUserID,
	}

	if err := h.db.Create(&userRole).Error; err != nil {
		response.InternalServerError(c, "failed to assign role")
		return
	}

	response.Success(c, gin.H{"message": "role assigned successfully"})
}

// RemoveRoleFromUser removes a role from a user.
// @Summary Remove role from user
// @Tags user-roles
// @Param id path int true "User ID"
// @Param roleId path int true "Role ID"
// @Success 204
// @Failure 400 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/users/{id}/roles/{roleId} [delete]
func (h *Handler) RemoveRoleFromUser(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid user ID")
		return
	}

	roleID, err := strconv.ParseUint(c.Param("roleId"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid role ID")
		return
	}

	// Delete user role assignment
	result := h.db.Where("user_id = ? AND role_id = ?", userID, roleID).Delete(&model.UserRole{})
	if result.Error != nil {
		response.InternalServerError(c, "failed to remove role")
		return
	}

	if result.RowsAffected == 0 {
		response.NotFound(c, "user-role association not found")
		return
	}

	response.NoContent(c)
}

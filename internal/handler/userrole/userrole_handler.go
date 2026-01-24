package userrole

import (
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"

	"paigram/internal/middleware"
	"paigram/internal/permission"
	"paigram/internal/response"
)

// Handler manages user role assignment HTTP requests.
type Handler struct {
	permMgr *permission.Manager
}

// NewHandler creates a new user role handler.
func NewHandler(permMgr *permission.Manager) *Handler {
	return &Handler{
		permMgr: permMgr,
	}
}

// RegisterRoutes registers user role management routes.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.GET("/:userId/roles", h.GetUserRoles)
	rg.POST("/:userId/roles", h.AssignRoleToUser)
	rg.DELETE("/:userId/roles/:roleId", h.RemoveRoleFromUser)
	rg.GET("/:userId/permissions", h.GetUserPermissions)
}

// AssignRoleRequest represents the request body for assigning a role to a user.
type AssignRoleRequest struct {
	RoleID uint64 `json:"role_id" binding:"required"`
}

// GetUserRoles returns all roles assigned to a user.
// @Summary Get user roles
// @Tags user-roles
// @Produce json
// @Param userId path int true "User ID"
// @Success 200 {array} model.Role
// @Failure 400 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/users/{userId}/roles [get]
func (h *Handler) GetUserRoles(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("userId"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid user ID")
		return
	}

	roles, err := h.permMgr.GetUserRoles(userID)
	if err != nil {
		response.InternalServerError(c, "failed to get user roles")
		return
	}

	response.Success(c, roles)
}

// GetUserPermissions returns all permissions for a user.
// @Summary Get user permissions
// @Tags user-roles
// @Produce json
// @Param userId path int true "User ID"
// @Success 200 {array} model.Permission
// @Failure 400 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/users/{userId}/permissions [get]
func (h *Handler) GetUserPermissions(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("userId"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid user ID")
		return
	}

	perms, err := h.permMgr.GetUserPermissions(userID)
	if err != nil {
		response.InternalServerError(c, "failed to get user permissions")
		return
	}

	response.Success(c, perms)
}

// AssignRoleToUser assigns a role to a user.
// @Summary Assign role to user
// @Tags user-roles
// @Accept json
// @Produce json
// @Param userId path int true "User ID"
// @Param body body AssignRoleRequest true "Role ID"
// @Success 200 {object} gin.H
// @Failure 400 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/users/{userId}/roles [post]
func (h *Handler) AssignRoleToUser(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("userId"), 10, 64)
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

	if err := h.permMgr.AssignRoleToUser(userID, req.RoleID, currentUserID); err != nil {
		if errors.Is(err, permission.ErrRoleNotFound) {
			response.NotFound(c, "role not found")
			return
		}
		if errors.Is(err, permission.ErrUserAlreadyHasRole) {
			response.BadRequest(c, "user already has this role")
			return
		}
		response.InternalServerError(c, "failed to assign role")
		return
	}

	response.Success(c, gin.H{"message": "role assigned successfully"})
}

// RemoveRoleFromUser removes a role from a user.
// @Summary Remove role from user
// @Tags user-roles
// @Param userId path int true "User ID"
// @Param roleId path int true "Role ID"
// @Success 204
// @Failure 400 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/users/{userId}/roles/{roleId} [delete]
func (h *Handler) RemoveRoleFromUser(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("userId"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid user ID")
		return
	}

	roleID, err := strconv.ParseUint(c.Param("roleId"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid role ID")
		return
	}

	if err := h.permMgr.RemoveRoleFromUser(userID, roleID); err != nil {
		response.InternalServerError(c, "failed to remove role")
		return
	}

	response.NoContent(c)
}

package role

import (
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/middleware"
	"paigram/internal/model"
	"paigram/internal/permission"
	"paigram/internal/response"
)

// Handler manages role-related HTTP requests.
type Handler struct {
	db      *gorm.DB
	permMgr *permission.Manager
}

// NewHandler creates a new role handler.
func NewHandler(db *gorm.DB, permMgr *permission.Manager) *Handler {
	return &Handler{
		db:      db,
		permMgr: permMgr,
	}
}

// RegisterRoutes registers role management routes.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.GET("", h.ListRoles)
	rg.GET("/:id", h.GetRole)
	rg.POST("", h.CreateRole)
	rg.PUT("/:id", h.UpdateRole)
	rg.DELETE("/:id", h.DeleteRole)
	rg.POST("/:id/permissions", h.AssignPermissionToRole)
	rg.DELETE("/:id/permissions/:permissionId", h.RemovePermissionFromRole)
}

// CreateRoleRequest represents the request body for creating a role.
type CreateRoleRequest struct {
	Name        string `json:"name" binding:"required,max=100"`
	DisplayName string `json:"display_name" binding:"required,max=255"`
	Description string `json:"description" binding:"max=512"`
}

// UpdateRoleRequest represents the request body for updating a role.
type UpdateRoleRequest struct {
	DisplayName string `json:"display_name" binding:"max=255"`
	Description string `json:"description" binding:"max=512"`
}

// AssignPermissionRequest represents the request body for assigning a permission to a role.
type AssignPermissionRequest struct {
	PermissionID uint64 `json:"permission_id" binding:"required"`
}

// ListRoles returns all roles.
//
// swagger:route GET /api/v1/roles roles listRoles
//
// List all roles with pagination support.
//
// This endpoint returns a paginated list of all roles in the system.
// Each role includes its basic information and counts of associated permissions and users.
//
// Produces:
// - application/json
//
// Responses:
//
//	200: paginatedResponse
//	400: errorResponse
//	500: errorResponse
//
// @Summary List all roles
// @Tags roles
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param sort_by query string false "Sort by field" default(created_at)
// @Param order query string false "Sort order" default(desc) enum(asc,desc)
// @Success 200 {object} response.PaginatedResponse
// @Failure 500 {object} gin.H
// @Router /api/v1/roles [get]
func (h *Handler) ListRoles(c *gin.Context) {
	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	sortBy := c.DefaultQuery("sort_by", "created_at")
	order := c.DefaultQuery("order", "desc")

	// Validate sort field
	allowedSortFields := map[string]bool{
		"id":         true,
		"name":       true,
		"created_at": true,
	}
	if !allowedSortFields[sortBy] {
		sortBy = "created_at"
	}

	// Validate order
	if order != "asc" && order != "desc" {
		order = "desc"
	}

	// Count total roles
	var total int64
	if err := h.db.Model(&model.Role{}).Count(&total).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to count roles", nil)
		return
	}

	// Get paginated roles
	var roles []model.Role
	offset := (page - 1) * pageSize
	orderClause := sortBy + " " + order

	if err := h.db.Preload("Permissions").
		Order(orderClause).
		Limit(pageSize).
		Offset(offset).
		Find(&roles).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to list roles", nil)
		return
	}

	response.SuccessWithPagination(c, roles, total, page, pageSize)
}

// GetRole returns a specific role by ID.
// @Summary Get role by ID
// @Tags roles
// @Produce json
// @Param id path int true "Role ID"
// @Success 200 {object} model.Role
// @Failure 400 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/roles/{id} [get]
func (h *Handler) GetRole(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid role ID")
		return
	}

	role, err := h.permMgr.GetRoleByID(id)
	if err != nil {
		if errors.Is(err, permission.ErrRoleNotFound) {
			response.NotFound(c, "role not found")
			return
		}
		response.InternalServerError(c, "failed to get role")
		return
	}

	response.Success(c, role)
}

// CreateRole creates a new role.
// @Summary Create a new role
// @Tags roles
// @Accept json
// @Produce json
// @Param body body CreateRoleRequest true "Role information"
// @Success 201 {object} model.Role
// @Failure 400 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/roles [post]
func (h *Handler) CreateRole(c *gin.Context) {
	var req CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	role, err := h.permMgr.CreateRole(req.Name, req.DisplayName, req.Description, false)
	if err != nil {
		response.InternalServerError(c, "failed to create role")
		return
	}

	response.Created(c, role)
}

// UpdateRole updates a role's information.
// @Summary Update a role
// @Tags roles
// @Accept json
// @Produce json
// @Param id path int true "Role ID"
// @Param body body UpdateRoleRequest true "Updated role information"
// @Success 200 {object} model.Role
// @Failure 400 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/roles/{id} [put]
func (h *Handler) UpdateRole(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid role ID")
		return
	}

	var req UpdateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	role, err := h.permMgr.UpdateRole(id, req.DisplayName, req.Description)
	if err != nil {
		if errors.Is(err, permission.ErrRoleNotFound) {
			response.NotFound(c, "role not found")
			return
		}
		response.InternalServerError(c, "failed to update role")
		return
	}

	response.Success(c, role)
}

// DeleteRole deletes a role by ID.
// @Summary Delete a role
// @Tags roles
// @Param id path int true "Role ID"
// @Success 204
// @Failure 400 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/roles/{id} [delete]
func (h *Handler) DeleteRole(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid role ID")
		return
	}

	if err := h.permMgr.DeleteRole(id); err != nil {
		if errors.Is(err, permission.ErrRoleNotFound) {
			response.NotFound(c, "role not found")
			return
		}
		if errors.Is(err, permission.ErrCannotDeleteSystemRole) {
			response.Forbidden(c, "cannot delete system role")
			return
		}
		response.InternalServerError(c, "failed to delete role")
		return
	}

	response.NoContent(c)
}

// AssignPermissionToRole assigns a permission to a role.
// @Summary Assign permission to role
// @Tags roles
// @Accept json
// @Produce json
// @Param id path int true "Role ID"
// @Param body body AssignPermissionRequest true "Permission ID"
// @Success 200 {object} gin.H
// @Failure 400 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/roles/{id}/permissions [post]
func (h *Handler) AssignPermissionToRole(c *gin.Context) {
	roleID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid role ID")
		return
	}

	var req AssignPermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	if err := h.permMgr.AssignPermissionToRole(roleID, req.PermissionID); err != nil {
		if errors.Is(err, permission.ErrRoleNotFound) {
			response.NotFound(c, "role not found")
			return
		}
		if errors.Is(err, permission.ErrPermissionNotFound) {
			response.NotFound(c, "permission not found")
			return
		}
		response.InternalServerError(c, "failed to assign permission")
		return
	}

	response.Success(c, gin.H{"message": "permission assigned successfully"})
}

// RemovePermissionFromRole removes a permission from a role.
// @Summary Remove permission from role
// @Tags roles
// @Param id path int true "Role ID"
// @Param permissionId path int true "Permission ID"
// @Success 204
// @Failure 400 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/roles/{id}/permissions/{permissionId} [delete]
func (h *Handler) RemovePermissionFromRole(c *gin.Context) {
	roleID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid role ID")
		return
	}

	permissionID, err := strconv.ParseUint(c.Param("permissionId"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid permission ID")
		return
	}

	if err := h.permMgr.RemovePermissionFromRole(roleID, permissionID); err != nil {
		if errors.Is(err, permission.ErrRoleNotFound) {
			response.NotFound(c, "role not found")
			return
		}
		if errors.Is(err, permission.ErrPermissionNotFound) {
			response.NotFound(c, "permission not found")
			return
		}
		response.InternalServerError(c, "failed to remove permission")
		return
	}

	response.NoContent(c)
}

// GetUserID retrieves the current user ID from context.
func (h *Handler) GetUserID(c *gin.Context) uint64 {
	userID, _ := middleware.GetUserID(c)
	return userID
}

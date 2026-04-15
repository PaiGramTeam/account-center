package permission

import (
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/model"
	"paigram/internal/response"
)

// Handler manages permission-related HTTP requests.
// Deprecated: This handler is deprecated. Use Casbin-based authorization instead.
type Handler struct {
	db *gorm.DB
}

// NewHandler creates a new permission handler.
// Deprecated: This handler is deprecated. Use Casbin-based authorization instead.
func NewHandler(db *gorm.DB) *Handler {
	return &Handler{
		db: db,
	}
}

// RegisterRoutes registers permission management routes.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.GET("", h.ListPermissions)
	rg.GET("/:id", h.GetPermission)
	rg.POST("", h.CreatePermission)
	rg.DELETE("/:id", h.DeletePermission)
}

// CreatePermissionRequest represents the request body for creating a permission.
type CreatePermissionRequest struct {
	Name        string `json:"name" binding:"required,max=100"`
	Resource    string `json:"resource" binding:"required,max=100"`
	Action      string `json:"action" binding:"required,max=50"`
	Description string `json:"description" binding:"max=512"`
}

// ListPermissions returns all permissions.
//
// swagger:route GET /api/v1/permissions permissions listPermissions
//
// List all permissions with pagination support.
//
// This endpoint returns a paginated list of all permissions in the system.
//
// Deprecated: This endpoint is deprecated. Use Casbin-based authorization instead.
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
// @Summary List all permissions
// @Tags permissions
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param sort_by query string false "Sort by field" default(created_at)
// @Param order query string false "Sort order" default(desc) enum(asc,desc)
// @Success 200 {object} response.PaginatedResponse
// @Failure 500 {object} gin.H
// @Router /api/v1/permissions [get]
// @deprecated
func (h *Handler) ListPermissions(c *gin.Context) {
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
		"resource":   true,
		"action":     true,
		"created_at": true,
	}
	if !allowedSortFields[sortBy] {
		sortBy = "created_at"
	}

	// Validate order
	if order != "asc" && order != "desc" {
		order = "desc"
	}

	// Count total permissions
	var total int64
	if err := h.db.Model(&model.Permission{}).Count(&total).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to count permissions", nil)
		return
	}

	// Get paginated permissions
	var permissions []model.Permission
	offset := (page - 1) * pageSize
	orderClause := sortBy + " " + order

	if err := h.db.Order(orderClause).
		Limit(pageSize).
		Offset(offset).
		Find(&permissions).Error; err != nil {
		response.InternalServerErrorWithCode(c, response.ErrCodeDatabaseError, "failed to list permissions", nil)
		return
	}

	response.SuccessWithPagination(c, permissions, total, page, pageSize)
}

// GetPermission returns a specific permission by ID.
// @Summary Get permission by ID
// @Tags permissions
// @Produce json
// @Param id path int true "Permission ID"
// @Success 200 {object} model.Permission
// @Failure 400 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/permissions/{id} [get]
// @deprecated
func (h *Handler) GetPermission(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid permission ID")
		return
	}

	var perm model.Permission
	if err := h.db.First(&perm, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFound(c, "permission not found")
			return
		}
		response.InternalServerError(c, "failed to get permission")
		return
	}

	response.Success(c, perm)
}

// CreatePermission creates a new permission.
// @Summary Create a new permission
// @Tags permissions
// @Accept json
// @Produce json
// @Param body body CreatePermissionRequest true "Permission information"
// @Success 201 {object} model.Permission
// @Failure 400 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/permissions [post]
// @deprecated
func (h *Handler) CreatePermission(c *gin.Context) {
	var req CreatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	perm := model.Permission{
		Name:        req.Name,
		Resource:    req.Resource,
		Action:      req.Action,
		Description: req.Description,
	}

	if err := h.db.Create(&perm).Error; err != nil {
		response.InternalServerError(c, "failed to create permission")
		return
	}

	response.Created(c, perm)
}

// DeletePermission deletes a permission by ID.
// @Summary Delete a permission
// @Tags permissions
// @Param id path int true "Permission ID"
// @Success 204
// @Failure 400 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/permissions/{id} [delete]
// @deprecated
func (h *Handler) DeletePermission(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "invalid permission ID")
		return
	}

	var perm model.Permission
	if err := h.db.First(&perm, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFound(c, "permission not found")
			return
		}
		response.InternalServerError(c, "failed to get permission")
		return
	}

	if err := h.db.Delete(&perm).Error; err != nil {
		response.InternalServerError(c, "failed to delete permission")
		return
	}

	response.NoContent(c)
}

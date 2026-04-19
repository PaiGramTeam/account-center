package adminaudit

import (
	"context"
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/response"
	serviceaudit "paigram/internal/service/audit"
)

// AuditReader describes the admin audit dependency.
type AuditReader interface {
	ListAuditLogs(context.Context, serviceaudit.ListAuditLogsFilter) ([]serviceaudit.AuditEventView, int64, error)
	GetAuditLog(context.Context, uint64) (*serviceaudit.AuditEventView, error)
}

// AuditHandler serves admin audit endpoints.
type AuditHandler struct {
	service AuditReader
}

// NewAuditHandler creates an admin audit handler.
func NewAuditHandler(service AuditReader) *AuditHandler {
	return &AuditHandler{service: service}
}

// swagger:route GET /api/v1/admin/audit-logs admin-audit listAuditLogs
//
// List unified audit logs.
//
// Returns paginated unified audit events for admin readers, with optional category and result filters.
//
// Produces:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Parameters:
//   - name: page
//     in: query
//     description: Page number starting from 1.
//     required: false
//     type: integer
//     default: 1
//   - name: page_size
//     in: query
//     description: Number of items per page.
//     required: false
//     type: integer
//     default: 20
//   - name: category
//     in: query
//     description: Filter audit events by category.
//     required: false
//     type: string
//   - name: result
//     in: query
//     description: Filter audit events by result.
//     required: false
//     type: string
//
// Responses:
//
//	200: adminAuditListResponse
//	401: adminAuditErrorResponse
//	403: adminAuditErrorResponse
//	500: adminAuditErrorResponse
//
// ListAuditLogs returns unified admin audit logs.
func (h *AuditHandler) ListAuditLogs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	items, total, err := h.service.ListAuditLogs(c.Request.Context(), serviceaudit.ListAuditLogsFilter{
		Category: c.Query("category"),
		Result:   c.Query("result"),
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		response.InternalServerError(c, "failed to load audit logs")
		return
	}
	response.Success(c, gin.H{
		"items":     items,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// swagger:route GET /api/v1/admin/audit-logs/{id} admin-audit getAuditLog
//
// Get one unified audit log.
//
// Returns the unified audit event identified by the provided id.
//
// Produces:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Parameters:
//   - name: id
//     in: path
//     description: Unified audit event id.
//     required: true
//     type: integer
//
// Responses:
//
//	200: adminAuditDetailResponse
//	400: adminAuditErrorResponse
//	401: adminAuditErrorResponse
//	403: adminAuditErrorResponse
//	404: adminAuditErrorResponse
//	500: adminAuditErrorResponse
func (h *AuditHandler) GetAuditLog(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		response.BadRequest(c, "invalid audit log id")
		return
	}

	item, err := h.service.GetAuditLog(c.Request.Context(), id)
	if err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			response.NotFound(c, "audit log not found")
		default:
			response.InternalServerError(c, "failed to load audit log")
		}
		return
	}

	response.Success(c, item)
}

package me

import (
	"context"
	"strconv"

	"github.com/gin-gonic/gin"

	"paigram/internal/middleware"
	"paigram/internal/response"
	serviceme "paigram/internal/service/me"
)

// ActivityReader describes the activity service dependency.
type ActivityReader interface {
	ListLogs(context.Context, uint64, int, int, string) ([]serviceme.ActivityLogView, int64, error)
}

// ActivityHandler serves /me activity-log endpoints.
type ActivityHandler struct {
	service ActivityReader
}

// NewActivityHandler creates an activity handler.
func NewActivityHandler(service ActivityReader) *ActivityHandler {
	return &ActivityHandler{service: service}
}

// swagger:route GET /api/v1/me/activity-logs me listMeActivityLogs
//
// List current-user activity logs.
//
// Returns paginated activity logs for the authenticated user.
//
// Produces:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//   200: meActivityLogsResponse
//   401: meErrorResponse
//   500: meErrorResponse
// ListLogs returns current-user activity logs.
func (h *ActivityHandler) ListLogs(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	logs, total, err := h.service.ListLogs(c.Request.Context(), userID, page, pageSize, c.Query("action_type"))
	if err != nil {
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "failed to load activity logs", nil)
		return
	}
	response.SuccessWithPagination(c, logs, total, page, pageSize)
}

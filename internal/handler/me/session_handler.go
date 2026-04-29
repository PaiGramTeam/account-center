package me

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"paigram/internal/logging"
	"paigram/internal/middleware"
	"paigram/internal/response"
	serviceme "paigram/internal/service/me"
	"paigram/internal/utils/safeerror"
)

type SessionView = serviceme.SessionView

// SessionReaderWriter describes the session service dependency.
type SessionReaderWriter interface {
	ListSessions(context.Context, uint64, int, int, string) ([]serviceme.SessionView, int64, error)
	RevokeSession(context.Context, uint64, uint64) error
}

// SessionHandler serves /me session endpoints.
type SessionHandler struct {
	service SessionReaderWriter
}

// NewSessionHandler creates a session handler.
func NewSessionHandler(service SessionReaderWriter) *SessionHandler {
	return &SessionHandler{service: service}
}

// swagger:route GET /api/v1/me/sessions me listMeSessions
//
// List current-user sessions.
//
// Returns the authenticated user's active sessions.
//
// Produces:
//   - application/json
//
// Parameters:
//   + name: page
//     in: query
//     type: integer
//   + name: page_size
//     in: query
//     type: integer
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//   200: meSessionsResponse
//   401: meErrorResponse
//   500: meErrorResponse
// ListSessions returns the current user's active sessions.
func (h *SessionHandler) ListSessions(c *gin.Context) {
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
	sessions, total, err := h.service.ListSessions(c.Request.Context(), userID, page, pageSize, bearerToken(c.GetHeader("Authorization")))
	if err != nil {
		response.InternalServerError(c, "failed to load sessions")
		return
	}
	response.SuccessWithPagination(c, sessions, total, page, pageSize)
}

// swagger:route DELETE /api/v1/me/sessions/{sessionId} me revokeMeSession
//
// Revoke current-user session.
//
// Revokes one session belonging to the authenticated user.
//
// Produces:
//   - application/json
//
// Security:
//   - BearerAuth: []
//
// Responses:
//
//   204:
//   400: meErrorResponse
//   401: meErrorResponse
//   404: meErrorResponse
//   500: meErrorResponse
// RevokeSession revokes one of the current user's sessions.
func (h *SessionHandler) RevokeSession(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok || userID == 0 {
		response.Unauthorized(c, "user not authenticated")
		return
	}
	sessionID, err := strconv.ParseUint(c.Param("sessionId"), 10, 64)
	if err != nil {
		response.BadRequestWithCode(c, response.ErrCodeInvalidInput, "invalid session id", nil)
		return
	}
	if err := h.service.RevokeSession(c.Request.Context(), userID, sessionID); err != nil {
		switch {
		case errors.Is(err, serviceme.ErrInvalidSessionID):
			response.BadRequestWithCode(c, response.ErrCodeInvalidInput, "invalid session id", nil)
		case errors.Is(err, serviceme.ErrSessionNotFound):
			response.NotFoundWithCode(c, "SESSION_NOT_FOUND", "session not found", nil)
		default:
			logging.Error("revoke session failed",
				zap.Error(err),
				zap.Uint64("user_id", userID),
				zap.Uint64("session_id", sessionID),
			)
			response.InternalServerError(c, safeerror.UserMessage(err))
		}
		return
	}
	response.NoContent(c)
}

func bearerToken(authHeader string) string {
	parts := strings.SplitN(strings.TrimSpace(authHeader), " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}
	return parts[1]
}

package adminsystem

import (
	"context"
	"errors"

	"github.com/gin-gonic/gin"

	"paigram/internal/middleware"
	"paigram/internal/response"
	servicesystemconfig "paigram/internal/service/systemconfig"
)

type LegalReader interface {
	ListDocuments(context.Context) ([]servicesystemconfig.LegalDocumentView, error)
	ListPublishedDocuments(context.Context) ([]servicesystemconfig.LegalDocumentView, error)
	UpsertDocuments(context.Context, []servicesystemconfig.UpsertLegalDocumentInput, uint64) ([]servicesystemconfig.LegalDocumentView, error)
}

type upsertLegalDocumentsRequest struct {
	Documents []servicesystemconfig.UpsertLegalDocumentInput `json:"documents"`
}

// LegalHandler serves versioned admin legal-document endpoints.
type LegalHandler struct {
	service LegalReader
}

// NewLegalHandler creates the admin system legal handler.
func NewLegalHandler(service LegalReader) *LegalHandler {
	return &LegalHandler{service: service}
}

// swagger:route GET /api/v1/admin/system/settings/legal admin-system getLegalDocuments
// List all legal document revisions, including drafts.
func (h *LegalHandler) GetPublishedDocuments(c *gin.Context) {
	documents, err := h.service.ListDocuments(c.Request.Context())
	if err != nil {
		response.InternalServerError(c, "failed to load legal documents")
		return
	}
	response.Success(c, gin.H{"documents": documents})
}

// swagger:route PATCH /api/v1/admin/system/settings/legal admin-system upsertLegalDocuments
// Upsert legal documents and return all revisions.
func (h *LegalHandler) UpsertDocuments(c *gin.Context) {
	var req upsertLegalDocumentsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid request payload")
		return
	}
	actorUserID, _ := middleware.GetUserID(c)
	documents, err := h.service.UpsertDocuments(c.Request.Context(), req.Documents, actorUserID)
	if err != nil {
		switch {
		case errors.Is(err, servicesystemconfig.ErrInvalidLegalDocument):
			response.BadRequest(c, "invalid legal document")
		default:
			response.InternalServerError(c, "failed to save legal documents")
		}
		return
	}
	response.Success(c, gin.H{"documents": documents})
}

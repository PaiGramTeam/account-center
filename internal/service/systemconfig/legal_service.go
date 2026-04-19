package systemconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"

	"paigram/internal/model"
)

var ErrInvalidLegalDocument = errors.New("invalid legal document")

// UpsertLegalDocumentInput is the admin payload for one legal document revision.
type UpsertLegalDocumentInput struct {
	DocumentType string `json:"document_type"`
	Version      string `json:"version"`
	Title        string `json:"title"`
	Content      string `json:"content"`
	Published    bool   `json:"published"`
}

// LegalDocumentView is the admin API projection for one legal document revision.
type LegalDocumentView struct {
	ID           uint64    `json:"id"`
	DocumentType string    `json:"document_type"`
	Version      string    `json:"version"`
	Title        string    `json:"title"`
	Content      string    `json:"content"`
	Published    bool      `json:"published"`
	PublishedAt  time.Time `json:"published_at,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// LegalService persists versioned legal documents.
type LegalService struct {
	db *gorm.DB
}

// NewLegalService creates a legal-documents service.
func NewLegalService(db *gorm.DB) *LegalService {
	return &LegalService{db: db}
}

// ListPublishedDocuments returns currently published admin legal documents.
func (s *LegalService) ListPublishedDocuments(ctx context.Context) ([]LegalDocumentView, error) {
	var rows []model.LegalDocument
	if err := s.db.WithContext(ctx).Where("published = ?", true).Order("document_type ASC, version DESC, id DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return buildLegalDocumentViews(rows), nil
}

// ListDocuments returns all admin-manageable legal document revisions, including drafts.
func (s *LegalService) ListDocuments(ctx context.Context) ([]LegalDocumentView, error) {
	var rows []model.LegalDocument
	if err := s.db.WithContext(ctx).Order("document_type ASC, version DESC, id DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return buildLegalDocumentViews(rows), nil
}

// UpsertDocuments stores versioned legal documents and returns all revisions.
func (s *LegalService) UpsertDocuments(ctx context.Context, inputs []UpsertLegalDocumentInput, actorUserID uint64) ([]LegalDocumentView, error) {
	if len(inputs) == 0 {
		return []LegalDocumentView{}, nil
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, input := range inputs {
			normalized, err := normalizeLegalDocumentInput(input)
			if err != nil {
				return err
			}

			var row model.LegalDocument
			findErr := tx.Where("document_type = ? AND version = ?", normalized.DocumentType, normalized.Version).First(&row).Error
			if findErr != nil && !errors.Is(findErr, gorm.ErrRecordNotFound) {
				return findErr
			}

			if normalized.Published {
				if err := tx.Model(&model.LegalDocument{}).Where("document_type = ?", normalized.DocumentType).Updates(map[string]any{
					"published":    false,
					"published_at": nil,
				}).Error; err != nil {
					return err
				}
			}

			row.DocumentType = normalized.DocumentType
			row.Version = normalized.Version
			row.Title = normalized.Title
			row.Content = normalized.Content
			row.Published = normalized.Published
			row.UpdatedBy = nullableUserID(actorUserID)
			if normalized.Published {
				row.PublishedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
			} else {
				row.PublishedAt = sql.NullTime{}
			}

			if row.ID == 0 {
				if err := tx.Create(&row).Error; err != nil {
					return err
				}
			} else {
				if err := tx.Save(&row).Error; err != nil {
					return err
				}
			}

			metadataJSON, err := json.Marshal(map[string]any{
				"document_type": row.DocumentType,
				"version":       row.Version,
				"published":     row.Published,
			})
			if err != nil {
				return err
			}
			if err := tx.Create(&model.AuditEvent{
				Category:     "legal_document",
				ActorType:    "user",
				ActorUserID:  nullableUserID(actorUserID),
				Action:       "upserted",
				TargetType:   "legal_document",
				TargetID:     row.DocumentType + ":" + row.Version,
				Result:       "success",
				MetadataJSON: string(metadataJSON),
				CreatedAt:    time.Now().UTC(),
			}).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return s.ListDocuments(ctx)
}

func normalizeLegalDocumentInput(input UpsertLegalDocumentInput) (UpsertLegalDocumentInput, error) {
	input.DocumentType = strings.TrimSpace(input.DocumentType)
	input.Version = strings.TrimSpace(input.Version)
	input.Title = strings.TrimSpace(input.Title)

	if input.DocumentType == "" || input.Version == "" || input.Title == "" {
		return UpsertLegalDocumentInput{}, ErrInvalidLegalDocument
	}
	switch input.DocumentType {
	case "terms", "privacy":
		return input, nil
	default:
		return UpsertLegalDocumentInput{}, ErrInvalidLegalDocument
	}
}

func buildLegalDocumentViews(rows []model.LegalDocument) []LegalDocumentView {
	views := make([]LegalDocumentView, 0, len(rows))
	for _, row := range rows {
		view := LegalDocumentView{
			ID:           row.ID,
			DocumentType: row.DocumentType,
			Version:      row.Version,
			Title:        row.Title,
			Content:      row.Content,
			Published:    row.Published,
			UpdatedAt:    row.UpdatedAt,
		}
		if row.PublishedAt.Valid {
			view.PublishedAt = row.PublishedAt.Time
		}
		views = append(views, view)
	}
	return views
}

package audit

import (
	"context"
	"encoding/json"

	"gorm.io/gorm"

	"paigram/internal/model"
)

// ListAuditLogsFilter narrows the unified audit query.
type ListAuditLogsFilter struct {
	Category string
	Result   string
	Page     int
	PageSize int
}

// AuditEventView is the admin API projection for one audit event.
type AuditEventView struct {
	ID           uint64         `json:"id"`
	Category     string         `json:"category"`
	ActorType    string         `json:"actor_type"`
	ActorUserID  uint64         `json:"actor_user_id,omitempty"`
	Action       string         `json:"action"`
	TargetType   string         `json:"target_type,omitempty"`
	TargetID     string         `json:"target_id,omitempty"`
	BindingID    *uint64        `json:"binding_id,omitempty"`
	Result       string         `json:"result"`
	ReasonCode   string         `json:"reason_code,omitempty"`
	RequestID    string         `json:"request_id,omitempty"`
	IP           string         `json:"ip,omitempty"`
	UserAgent    string         `json:"user_agent,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	MetadataJSON string         `json:"metadata_json,omitempty"`
	CreatedAt    string         `json:"created_at"`
}

// AuditService serves the unified admin audit API.
type AuditService struct {
	db *gorm.DB
}

// NewAuditService creates a unified audit service.
func NewAuditService(db *gorm.DB) *AuditService {
	return &AuditService{db: db}
}

// ListAuditLogs returns filtered audit events for admin reads.
func (s *AuditService) ListAuditLogs(ctx context.Context, filter ListAuditLogsFilter) ([]AuditEventView, int64, error) {
	query := s.db.WithContext(ctx).Model(&model.AuditEvent{})
	if filter.Category != "" {
		query = query.Where("category = ?", filter.Category)
	}
	if filter.Result != "" {
		query = query.Where("result = ?", filter.Result)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var rows []model.AuditEvent
	offset := (filter.Page - 1) * filter.PageSize
	if err := query.Order("created_at DESC").Limit(filter.PageSize).Offset(offset).Find(&rows).Error; err != nil {
		return nil, 0, err
	}

	items := make([]AuditEventView, 0, len(rows))
	for _, row := range rows {
		items = append(items, buildAuditEventView(row))
	}

	return items, total, nil
}

// GetAuditLog returns one unified audit event by id.
func (s *AuditService) GetAuditLog(ctx context.Context, id uint64) (*AuditEventView, error) {
	var row model.AuditEvent
	if err := s.db.WithContext(ctx).First(&row, id).Error; err != nil {
		return nil, err
	}
	view := buildAuditEventView(row)
	return &view, nil
}

func buildAuditEventView(row model.AuditEvent) AuditEventView {
	item := AuditEventView{
		ID:           row.ID,
		Category:     row.Category,
		ActorType:    row.ActorType,
		Action:       row.Action,
		TargetType:   row.TargetType,
		TargetID:     row.TargetID,
		Result:       row.Result,
		ReasonCode:   row.ReasonCode,
		RequestID:    row.RequestID,
		IP:           row.IP,
		UserAgent:    row.UserAgent,
		MetadataJSON: row.MetadataJSON,
		CreatedAt:    row.CreatedAt.UTC().Format("2006-01-02T15:04:05.000Z07:00"),
	}
	if row.ActorUserID.Valid {
		item.ActorUserID = uint64(row.ActorUserID.Int64)
	}
	if row.BindingID.Valid {
		bindingID := uint64(row.BindingID.Int64)
		item.BindingID = &bindingID
	}
	if row.MetadataJSON != "" {
		var metadata map[string]any
		if err := json.Unmarshal([]byte(row.MetadataJSON), &metadata); err == nil && metadata != nil {
			item.Metadata = metadata
		}
	}
	return item
}

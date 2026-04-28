package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	grpcmetadata "google.golang.org/grpc/metadata"
	"gorm.io/gorm"

	"paigram/internal/model"
)

type contextKey string

const requestIDContextKey contextKey = "audit_request_id"

// WriteInput describes one canonical unified audit event.
type WriteInput struct {
	Category    string
	ActorType   string
	ActorUserID *uint64
	Action      string
	TargetType  string
	TargetID    string
	BindingID   *uint64
	OwnerUserID *uint64
	Result      string
	ReasonCode  string
	RequestID   string
	IP          string
	UserAgent   string
	Metadata    map[string]any
}

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

// Record writes one unified audit event using the service DB.
func (s *AuditService) Record(ctx context.Context, input WriteInput) error {
	return Record(ctx, s.db, input)
}

// Record writes one unified audit event.
func Record(ctx context.Context, db *gorm.DB, input WriteInput) error {
	return RecordTx(withContext(db, ctx), input)
}

// RecordTx writes one unified audit event within the current transaction.
func RecordTx(tx *gorm.DB, input WriteInput) error {
	if tx == nil {
		return fmt.Errorf("audit write: db is nil")
	}
	var ctx context.Context
	if tx.Statement != nil {
		ctx = tx.Statement.Context
	}
	row, err := buildAuditEventRow(ctx, input)
	if err != nil {
		return err
	}
	return tx.Create(&row).Error
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

func buildAuditEventRow(ctx context.Context, input WriteInput) (model.AuditEvent, error) {
	requestID := strings.TrimSpace(input.RequestID)
	if requestID == "" {
		requestID = requestIDFromContext(ctx)
	}
	metadataJSON, err := buildMetadataJSON(input, requestID)
	if err != nil {
		return model.AuditEvent{}, err
	}
	result := strings.TrimSpace(input.Result)
	if result == "" {
		result = "success"
	}
	row := model.AuditEvent{
		Category:     strings.TrimSpace(input.Category),
		ActorType:    strings.TrimSpace(input.ActorType),
		Action:       strings.TrimSpace(input.Action),
		TargetType:   strings.TrimSpace(input.TargetType),
		TargetID:     strings.TrimSpace(input.TargetID),
		Result:       result,
		ReasonCode:   strings.TrimSpace(input.ReasonCode),
		RequestID:    requestID,
		IP:           strings.TrimSpace(input.IP),
		UserAgent:    strings.TrimSpace(input.UserAgent),
		MetadataJSON: metadataJSON,
		CreatedAt:    time.Now().UTC(),
	}
	if input.ActorUserID != nil && *input.ActorUserID != 0 {
		row.ActorUserID = nullUint64(*input.ActorUserID)
	}
	if input.BindingID != nil && *input.BindingID != 0 {
		row.BindingID = nullUint64(*input.BindingID)
	}
	return row, nil
}

func buildMetadataJSON(input WriteInput, requestID string) (string, error) {
	metadata := make(map[string]any, len(input.Metadata)+6)
	for key, value := range input.Metadata {
		metadata[key] = value
	}
	actor := map[string]any{"type": strings.TrimSpace(input.ActorType)}
	if input.ActorUserID != nil && *input.ActorUserID != 0 {
		actor["user_id"] = *input.ActorUserID
	}
	target := map[string]any{
		"type": strings.TrimSpace(input.TargetType),
		"id":   strings.TrimSpace(input.TargetID),
	}
	if input.BindingID != nil && *input.BindingID != 0 {
		target["binding_id"] = *input.BindingID
	}
	owner := map[string]any{"user_id": nil}
	if input.OwnerUserID != nil && *input.OwnerUserID != 0 {
		owner["user_id"] = *input.OwnerUserID
	}
	metadata["actor"] = actor
	metadata["action"] = strings.TrimSpace(input.Action)
	metadata["target"] = target
	metadata["owner"] = owner
	metadata["result"] = strings.TrimSpace(input.Result)
	metadata["reason"] = strings.TrimSpace(input.ReasonCode)
	metadata["request_id"] = requestID
	body, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func requestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return generatedRequestID()
	}
	if value, ok := ctx.Value(requestIDContextKey).(string); ok && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	if md, ok := grpcmetadata.FromIncomingContext(ctx); ok {
		if values := md.Get("x-request-id"); len(values) > 0 && strings.TrimSpace(values[0]) != "" {
			return strings.TrimSpace(values[0])
		}
	}
	return generatedRequestID()
}

func generatedRequestID() string {
	return fmt.Sprintf("audit-%d", time.Now().UTC().UnixNano())
}

func nullUint64(value uint64) sql.NullInt64 {
	return sql.NullInt64{Int64: int64(value), Valid: true}
}

func withContext(db *gorm.DB, ctx context.Context) *gorm.DB {
	if ctx == nil {
		return db
	}
	return db.WithContext(ctx)
}

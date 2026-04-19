package me

import (
	"context"
	"time"

	"gorm.io/gorm"

	"paigram/internal/model"
)

// ActivityLogView is the /me activity-log projection.
type ActivityLogView struct {
	ID        uint64    `json:"id"`
	Action    string    `json:"action"`
	Details   string    `json:"details,omitempty"`
	IP        string    `json:"ip,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ActivityService serves /me activity logs.
type ActivityService struct {
	db *gorm.DB
}

// NewActivityService creates an activity service.
func NewActivityService(db *gorm.DB) *ActivityService {
	return &ActivityService{db: db}
}

// ListLogs returns paginated current-user audit logs.
func (s *ActivityService) ListLogs(ctx context.Context, userID uint64, page, pageSize int, actionType string) ([]ActivityLogView, int64, error) {
	query := s.db.WithContext(ctx).Model(&model.AuditLog{}).Where("user_id = ?", userID)
	if actionType != "" {
		query = query.Where("action = ?", actionType)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var logs []model.AuditLog
	offset := (page - 1) * pageSize
	if err := query.Order("created_at DESC").Limit(pageSize).Offset(offset).Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	views := make([]ActivityLogView, 0, len(logs))
	for _, log := range logs {
		views = append(views, ActivityLogView{ID: log.ID, Action: log.Action, Details: log.Details, IP: log.IP, CreatedAt: log.CreatedAt})
	}
	return views, total, nil
}

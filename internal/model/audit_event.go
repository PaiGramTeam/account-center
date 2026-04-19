package model

import (
	"database/sql"
	"time"
)

// AuditEvent stores a unified admin-readable audit event.
type AuditEvent struct {
	ID           uint64        `gorm:"primaryKey"`
	Category     string        `gorm:"size:64;not null;index"`
	ActorType    string        `gorm:"size:32;not null;index"`
	ActorUserID  sql.NullInt64 `gorm:"type:bigint unsigned;index"`
	Action       string        `gorm:"size:128;not null;index"`
	TargetType   string        `gorm:"size:64;index"`
	TargetID     string        `gorm:"size:191;index"`
	BindingID    sql.NullInt64 `gorm:"type:bigint unsigned;index"`
	Result       string        `gorm:"size:32;not null;index"`
	ReasonCode   string        `gorm:"size:64;index"`
	RequestID    string        `gorm:"size:128;index"`
	IP           string        `gorm:"size:128"`
	UserAgent    string        `gorm:"size:512"`
	MetadataJSON string        `gorm:"type:json"`
	CreatedAt    time.Time     `gorm:"not null;default:CURRENT_TIMESTAMP(3);index"`
}

func (AuditEvent) TableName() string {
	return "audit_events"
}

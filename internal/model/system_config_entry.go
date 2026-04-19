package model

import (
	"database/sql"
	"time"

	"gorm.io/gorm"
)

// SystemConfigEntry stores one grouped admin system settings document.
type SystemConfigEntry struct {
	ID           uint64         `gorm:"primaryKey"`
	ConfigDomain string         `gorm:"size:64;uniqueIndex;not null"`
	PayloadJSON  string         `gorm:"type:json;not null"`
	Version      uint64         `gorm:"not null;default:1"`
	UpdatedBy    sql.NullInt64  `gorm:"type:bigint unsigned;index"`
	CreatedAt    time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	UpdatedAt    time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	DeletedAt    gorm.DeletedAt `gorm:"index"`
}

func (SystemConfigEntry) TableName() string {
	return "system_config_entries"
}

package model

import (
	"database/sql"
	"time"

	"gorm.io/gorm"
)

// LegalDocument stores a versioned legal text such as terms or privacy policy.
type LegalDocument struct {
	ID           uint64         `gorm:"primaryKey"`
	DocumentType string         `gorm:"size:32;not null;uniqueIndex:uk_legal_document_type_version,priority:1;index"`
	Version      string         `gorm:"size:64;not null;uniqueIndex:uk_legal_document_type_version,priority:2"`
	Title        string         `gorm:"size:255;not null"`
	Content      string         `gorm:"type:longtext;not null"`
	Published    bool           `gorm:"not null;default:false;index"`
	PublishedAt  sql.NullTime   `gorm:"type:datetime(3)"`
	UpdatedBy    sql.NullInt64  `gorm:"type:bigint unsigned;index"`
	CreatedAt    time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	UpdatedAt    time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	DeletedAt    gorm.DeletedAt `gorm:"index"`
}

func (LegalDocument) TableName() string {
	return "legal_documents"
}

package model

import (
	"database/sql"
	"time"

	"gorm.io/gorm"
)

// Bot represents a registered bot client
type Bot struct {
	ID                      string       `gorm:"primaryKey;size:64"`
	Name                    string       `gorm:"size:255;not null"`
	Description             string       `gorm:"type:text"`
	Type                    string       `gorm:"size:32;not null;default:'OTHER'"`
	Status                  string       `gorm:"size:32;not null;default:'ACTIVE';index"`
	AllowLegacyBindingWrite bool         `gorm:"not null;default:false"`
	OwnerUserID             uint64       `gorm:"index;not null"`
	APIKey                  string       `gorm:"size:255;uniqueIndex;not null"`
	APISecret               string       `gorm:"size:512;not null"` // Should be hashed
	Scopes                  string       `gorm:"size:1024"`         // JSON array of scopes
	Metadata                string       `gorm:"type:json"`         // Custom metadata (JSON)
	LastActiveAt            sql.NullTime `gorm:"type:datetime(3)"`
	CreatedAt               time.Time
	UpdatedAt               time.Time
	DeletedAt               gorm.DeletedAt `gorm:"index"`
}

// BotToken represents an active access token for a bot
type BotToken struct {
	ID                  uint64       `gorm:"primaryKey"`
	BotID               string       `gorm:"size:64;index;not null"`
	AccessTokenHash     string       `gorm:"size:64;uniqueIndex;not null"` // SHA-256 hash of access token
	RefreshTokenHash    string       `gorm:"size:64;uniqueIndex;not null"` // SHA-256 hash of refresh token
	RateLimitEnabled    bool         `gorm:"default:true;not null"`
	RateLimitTimeWindow *int64       `gorm:"type:bigint"` // Time window in milliseconds
	RateLimitMax        *int         `gorm:"type:int"`    // Max requests within time window
	RequestCount        int          `gorm:"default:0;not null"`
	LastRequest         sql.NullTime `gorm:"type:datetime(3);index"`
	Metadata            string       `gorm:"type:json"` // Custom metadata for this token (JSON)
	ExpiresAt           time.Time    `gorm:"index;not null"`
	CreatedAt           time.Time
	RevokedAt           sql.NullTime `gorm:"type:datetime(3)"`

	// FamilyID groups all rotated tokens that descend from a single login. Reuse
	// detection on RefreshBotToken revokes the entire family. Allocated by
	// BotLogin and preserved verbatim across rotations performed by RefreshBotToken.
	FamilyID string `gorm:"column:family_id;size:36;not null;default:'';index"`
	// Status tracks the lifecycle of this row: 'active' (current), 'rotated'
	// (legitimately superseded by a newer row in the same family) or 'revoked'
	// (invalidated, typically by reuse detection on the family).
	Status string `gorm:"column:status;size:32;not null;default:'active';index"`
	// RevokedReason captures *why* a row moved to 'revoked'. Populated alongside
	// RevokedAt; empty for 'active' / 'rotated' rows.
	RevokedReason string `gorm:"column:revoked_reason;size:64;not null;default:''"`

	Bot Bot `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

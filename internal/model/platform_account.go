package model

import (
	"database/sql"
	"time"

	"gorm.io/gorm"
)

// PlatformAccountRefStatus represents the lifecycle state of a referenced platform account.
type PlatformAccountRefStatus string

const (
	PlatformAccountRefStatusActive   PlatformAccountRefStatus = "active"
	PlatformAccountRefStatusInactive PlatformAccountRefStatus = "inactive"
	PlatformAccountRefStatusRevoked  PlatformAccountRefStatus = "revoked"
)

// BotIdentity links a bot-specific external user to a unified account-center user.
type BotIdentity struct {
	ID               uint64         `gorm:"primaryKey"`
	UserID           uint64         `gorm:"uniqueIndex:uk_bot_identities_user_bot,priority:1;not null;index"`
	BotID            string         `gorm:"size:64;uniqueIndex:uk_bot_identities_bot_external,priority:1;uniqueIndex:uk_bot_identities_user_bot,priority:2;not null"`
	ExternalUserID   string         `gorm:"size:191;uniqueIndex:uk_bot_identities_bot_external,priority:2;not null"`
	ExternalUsername sql.NullString `gorm:"size:255"`
	LinkedAt         time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	CreatedAt        time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	UpdatedAt        time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	DeletedAt        gorm.DeletedAt `gorm:"index"`

	User User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Bot  Bot  `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:BotID;references:ID"`
}

func (BotIdentity) TableName() string {
	return "bot_identities"
}

// PlatformAccountRef stores a non-sensitive reference to an external platform account.
type PlatformAccountRef struct {
	ID                 uint64                   `gorm:"primaryKey"`
	UserID             uint64                   `gorm:"not null;index:idx_platform_account_refs_user_platform,priority:1"`
	Platform           string                   `gorm:"size:64;not null;uniqueIndex:uk_platform_account_refs_platform_account,priority:1;index:idx_platform_account_refs_user_platform,priority:2"`
	PlatformServiceKey string                   `gorm:"size:128;not null"`
	PlatformAccountID  string                   `gorm:"size:191;not null;uniqueIndex:uk_platform_account_refs_platform_account,priority:2"`
	DisplayName        string                   `gorm:"size:255;not null"`
	Status             PlatformAccountRefStatus `gorm:"size:32;not null;default:'active';index"`
	MetaJSON           sql.NullString           `gorm:"type:json"`
	CreatedAt          time.Time                `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	UpdatedAt          time.Time                `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	DeletedAt          gorm.DeletedAt           `gorm:"index"`

	User User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

func (PlatformAccountRef) TableName() string {
	return "platform_account_refs"
}

// BotAccountGrant records the scopes a bot may use for a platform account reference.
type BotAccountGrant struct {
	ID                   uint64         `gorm:"primaryKey"`
	UserID               uint64         `gorm:"not null;index"`
	BotID                string         `gorm:"size:64;not null;uniqueIndex:uk_bot_account_grants_bot_account,priority:1"`
	PlatformAccountRefID uint64         `gorm:"not null;uniqueIndex:uk_bot_account_grants_bot_account,priority:2;index:idx_bot_account_grants_platform_account_ref_id"`
	Scopes               string         `gorm:"type:json;not null"`
	GrantedAt            time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	RevokedAt            sql.NullTime   `gorm:"type:datetime(3);index"`
	CreatedAt            time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	UpdatedAt            time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	DeletedAt            gorm.DeletedAt `gorm:"index"`

	User               User               `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Bot                Bot                `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:BotID;references:ID"`
	PlatformAccountRef PlatformAccountRef `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

func (BotAccountGrant) TableName() string {
	return "bot_account_grants"
}

package model

import (
	"time"

	"gorm.io/gorm"
)

// BotAuthorization represents user authorization for a bot application
type BotAuthorization struct {
	ID           uint64         `json:"id" gorm:"primaryKey"`
	UserID       uint64         `json:"user_id" gorm:"uniqueIndex:idx_user_bot;not null"`
	BotID        string         `json:"bot_id" gorm:"size:64;uniqueIndex:idx_user_bot;not null"`
	Scopes       string         `json:"scopes" gorm:"size:1024;not null"` // JSON array of authorized scopes
	AuthorizedAt time.Time      `json:"authorized_at" gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	LastUsedAt   *time.Time     `json:"last_used_at" gorm:"type:datetime(3)"`
	ExpiresAt    *time.Time     `json:"expires_at" gorm:"type:datetime(3);index"`
	RevokedAt    *time.Time     `json:"revoked_at" gorm:"type:datetime(3);index"`
	RevokedBy    *uint64        `json:"revoked_by" gorm:"index"`
	RevokeReason string         `json:"revoke_reason" gorm:"size:255"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"index"`

	// Relations
	User User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Bot  Bot  `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

// BotAuthorizationResponse represents the API response for bot authorization
type BotAuthorizationResponse struct {
	ID           uint64     `json:"id"`
	BotID        string     `json:"bot_id"`
	BotName      string     `json:"bot_name"`
	BotType      string     `json:"bot_type"`
	Description  string     `json:"description"`
	Scopes       []string   `json:"scopes"`
	AuthorizedAt time.Time  `json:"authorized_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

// BotPermission represents a permission that can be granted to a bot
type BotPermission struct {
	ID          uint64    `json:"id" gorm:"primaryKey"`
	Code        string    `json:"code" gorm:"size:100;uniqueIndex;not null"`
	Name        string    `json:"name" gorm:"size:100;not null"`
	Description string    `json:"description" gorm:"size:500"`
	Category    string    `json:"category" gorm:"size:50;not null;default:'general'"`
	IsActive    bool      `json:"is_active" gorm:"default:true"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// BotPermissionResponse represents the API response for bot permissions
type BotPermissionResponse struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

// TableName returns the table name for BotAuthorization
func (BotAuthorization) TableName() string {
	return "bot_authorizations"
}

// TableName returns the table name for BotPermission
func (BotPermission) TableName() string {
	return "bot_permissions"
}

// IsValid checks if the authorization is still valid
func (ba *BotAuthorization) IsValid() bool {
	if ba.RevokedAt != nil {
		return false
	}
	if ba.ExpiresAt != nil && ba.ExpiresAt.Before(time.Now()) {
		return false
	}
	return true
}

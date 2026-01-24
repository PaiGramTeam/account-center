package model

import (
	"database/sql"
	"time"
)

// UserTwoFactor stores 2FA configuration for users
type UserTwoFactor struct {
	ID          uint64       `gorm:"primaryKey"`
	UserID      uint64       `gorm:"uniqueIndex;not null"`
	Secret      string       `gorm:"size:255;not null"` // Encrypted TOTP secret
	BackupCodes string       `gorm:"type:text"`         // JSON array of encrypted backup codes
	EnabledAt   time.Time    `gorm:"not null"`
	LastUsedAt  sql.NullTime `gorm:"type:datetime(3)"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// UserDevice represents a user's login device/session
type UserDevice struct {
	ID           uint64       `gorm:"primaryKey"`
	UserID       uint64       `gorm:"index;not null"`
	DeviceID     string       `gorm:"size:255;uniqueIndex;not null"`
	DeviceName   string       `gorm:"size:255"`
	DeviceType   string       `gorm:"size:64"` // mobile, desktop, tablet, etc.
	OS           string       `gorm:"size:64"`
	Browser      string       `gorm:"size:64"`
	IP           string       `gorm:"size:128"`
	Location     string       `gorm:"size:255"` // City, Country
	LastActiveAt time.Time    `gorm:"not null"`
	TrustExpiry  sql.NullTime `gorm:"type:datetime(3)"` // For trusted device feature
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// LoginLog represents user login history
type LoginLog struct {
	ID            uint64    `gorm:"primaryKey"`
	UserID        uint64    `gorm:"index;not null"`
	LoginType     LoginType `gorm:"size:32;not null"`
	IP            string    `gorm:"size:128"`
	UserAgent     string    `gorm:"size:512"`
	Device        string    `gorm:"size:255"`
	Location      string    `gorm:"size:255"`
	Status        string    `gorm:"size:32;not null"` // success, failed
	FailureReason string    `gorm:"size:255"`
	CreatedAt     time.Time
}

// AuditLog represents user activity logs
type AuditLog struct {
	ID         uint64 `gorm:"primaryKey"`
	UserID     uint64 `gorm:"index;not null"`
	Action     string `gorm:"size:128;not null;index"`
	Resource   string `gorm:"size:128"`
	ResourceID uint64 `gorm:"index"`
	OldValue   string `gorm:"type:text"`
	NewValue   string `gorm:"type:text"`
	IP         string `gorm:"size:128"`
	UserAgent  string `gorm:"size:512"`
	Details    string `gorm:"type:text"` // JSON details
	CreatedAt  time.Time
}

// PasswordResetToken stores password reset tokens
type PasswordResetToken struct {
	ID        uint64       `gorm:"primaryKey"`
	UserID    uint64       `gorm:"index;not null"`
	Token     string       `gorm:"size:255;uniqueIndex;not null"`
	ExpiresAt time.Time    `gorm:"not null"`
	UsedAt    sql.NullTime `gorm:"type:datetime(3)"`
	CreatedAt time.Time
}

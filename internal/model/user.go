package model

import (
	"database/sql"
	"time"

	"gorm.io/gorm"
)

// UserStatus represents the lifecycle stage of an account.
type UserStatus string

const (
	UserStatusPending   UserStatus = "pending"
	UserStatusActive    UserStatus = "active"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusDeleted   UserStatus = "deleted"
)

// LoginType enumerates supported login mechanisms.
type LoginType string

const (
	LoginTypeEmail LoginType = "email"
	LoginTypeOAuth LoginType = "oauth"
)

// User models the core user entity.
type User struct {
	ID               uint64         `gorm:"primaryKey"`
	PrimaryLoginType LoginType      `gorm:"size:32;not null;index"`
	Status           UserStatus     `gorm:"size:32;not null;default:'pending';index"`
	LastLoginAt      sql.NullTime   `gorm:"type:datetime(3);index"`
	CreatedAt        time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	UpdatedAt        time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	DeletedAt        gorm.DeletedAt `gorm:"index"`

	Profile     UserProfile      `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Credentials []UserCredential `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Emails      []UserEmail      `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Sessions    []UserSession    `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

// UserProfile stores display information for a user.
type UserProfile struct {
	ID          uint64 `gorm:"primaryKey"`
	UserID      uint64 `gorm:"uniqueIndex;not null"`
	DisplayName string `gorm:"size:255;not null"`
	AvatarURL   string `gorm:"size:512"`
	Bio         string `gorm:"type:text"`
	Locale      string `gorm:"size:10;default:'en_US'"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// UserCredential stores authentication secrets per provider.
type UserCredential struct {
	ID                uint64       `gorm:"primaryKey"`
	UserID            uint64       `gorm:"index;not null"`
	Provider          string       `gorm:"size:64;not null;index:user_provider,priority:1"`
	ProviderAccountID string       `gorm:"size:255;not null;index:user_provider,priority:2"`
	PasswordHash      string       `gorm:"size:255"`
	AccessToken       string       `gorm:"size:1024"`
	RefreshToken      string       `gorm:"size:1024"`
	TokenExpiry       sql.NullTime `gorm:"type:datetime(3)"`
	Scopes            string       `gorm:"size:512"`
	LastSyncAt        sql.NullTime `gorm:"type:datetime(3)"`
	Metadata          string       `gorm:"type:text"`
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// UserEmail keeps track of user email addresses and verification state.
type UserEmail struct {
	ID                 uint64       `gorm:"primaryKey"`
	UserID             uint64       `gorm:"index;not null"`
	Email              string       `gorm:"size:255;not null;index"`
	IsPrimary          bool         `gorm:"default:false"`
	VerifiedAt         sql.NullTime `gorm:"type:datetime(3)"`
	VerificationToken  string       `gorm:"size:255;index"`
	VerificationExpiry sql.NullTime `gorm:"type:datetime(3)"`
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// UserOAuthState stores temporary OAuth states for CSRF protection.
type UserOAuthState struct {
	ID         uint64    `gorm:"primaryKey"`
	Provider   string    `gorm:"size:64;index"`
	State      string    `gorm:"size:255;uniqueIndex"`
	RedirectTo string    `gorm:"size:512"`
	Nonce      string    `gorm:"size:255"`
	ExpiresAt  time.Time `gorm:"index"`
	CreatedAt  time.Time
}

// UserSession represents an access/refresh token pair for a user.
type UserSession struct {
	ID               uint64    `gorm:"primaryKey"`
	UserID           uint64    `gorm:"index;not null"`
	AccessTokenHash  string    `gorm:"size:64;uniqueIndex;not null"` // SHA-256 hash of access token
	RefreshTokenHash string    `gorm:"size:64;uniqueIndex;not null"` // SHA-256 hash of refresh token
	AccessExpiry     time.Time `gorm:"index"`
	RefreshExpiry    time.Time `gorm:"index"`
	UserAgent        string    `gorm:"size:512"`
	ClientIP         string    `gorm:"size:128"`
	CreatedAt        time.Time
	UpdatedAt        time.Time
	RevokedAt        sql.NullTime `gorm:"type:datetime(3)"`
	RevokedReason    string       `gorm:"size:255"`
}

// LoginAudit captures login attempts for monitoring.
type LoginAudit struct {
	ID        uint64        `gorm:"primaryKey"`
	UserID    sql.NullInt64 `gorm:"index"`
	Provider  string        `gorm:"size:64;index"`
	Success   bool          `gorm:"index"`
	ClientIP  string        `gorm:"size:128"`
	UserAgent string        `gorm:"size:512"`
	Message   string        `gorm:"size:512"`
	CreatedAt time.Time
}

func (UserOAuthState) TableName() string {
	return "user_oauth_states"
}

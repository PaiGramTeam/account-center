package model

import (
	"database/sql"
	"time"

	"gorm.io/gorm"
)

// PlatformAccountBindingStatus tracks the lifecycle of a bound external account.
type PlatformAccountBindingStatus string

const (
	PlatformAccountBindingStatusPendingBind       PlatformAccountBindingStatus = "pending_bind"
	PlatformAccountBindingStatusActive            PlatformAccountBindingStatus = "active"
	PlatformAccountBindingStatusCredentialInvalid PlatformAccountBindingStatus = "credential_invalid"
	PlatformAccountBindingStatusRefreshRequired   PlatformAccountBindingStatus = "refresh_required"
	PlatformAccountBindingStatusDisabled          PlatformAccountBindingStatus = "disabled"
	PlatformAccountBindingStatusDeleting          PlatformAccountBindingStatus = "deleting"
	PlatformAccountBindingStatusDeleteFailed      PlatformAccountBindingStatus = "delete_failed"
	PlatformAccountBindingStatusDeleted           PlatformAccountBindingStatus = "deleted"
)

// ConsumerGrantStatus tracks whether a consumer may use a binding.
type ConsumerGrantStatus string

const (
	ConsumerGrantStatusActive  ConsumerGrantStatus = "active"
	ConsumerGrantStatusRevoked ConsumerGrantStatus = "revoked"
)

// PlatformAccountBinding is the control-plane owner record for one external account.
type PlatformAccountBinding struct {
	ID                 uint64                       `gorm:"primaryKey"`
	OwnerUserID        uint64                       `gorm:"not null;index:idx_platform_account_bindings_owner"`
	Platform           string                       `gorm:"size:64;not null"`
	ExternalAccountKey string                       `gorm:"size:191;not null"`
	PlatformServiceKey string                       `gorm:"size:128;not null"`
	DisplayName        string                       `gorm:"size:255;not null"`
	Status             PlatformAccountBindingStatus `gorm:"size:32;not null;default:'pending_bind';index:idx_platform_account_bindings_status"`
	// PrimaryProfileID is validated in SQL against the composite (binding_id, id) key on platform_account_profiles.
	PrimaryProfileID sql.NullInt64  `gorm:"type:bigint unsigned;index:idx_platform_account_bindings_primary_profile_id"`
	LastSyncedAt     sql.NullTime   `gorm:"type:datetime(3)"`
	CreatedAt        time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	UpdatedAt        time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	DeletedAt        gorm.DeletedAt `gorm:"index"`

	Owner          User                     `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:OwnerUserID;references:ID"`
	Profiles       []PlatformAccountProfile `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:BindingID;references:ID"`
	ConsumerGrants []ConsumerGrant          `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:BindingID;references:ID"`
}

func (PlatformAccountBinding) TableName() string {
	return "platform_account_bindings"
}

// PlatformAccountProfile is a searchable projection under a binding.
// SQL enforces at most one primary row per binding with a generated marker column.
type PlatformAccountProfile struct {
	ID                 uint64        `gorm:"primaryKey"`
	BindingID          uint64        `gorm:"not null;uniqueIndex:uk_platform_account_profiles_binding_key,priority:1;index:idx_platform_account_profiles_binding_id"`
	PlatformProfileKey string        `gorm:"size:191;not null;uniqueIndex:uk_platform_account_profiles_binding_key,priority:2"`
	GameBiz            string        `gorm:"size:64;not null"`
	Region             string        `gorm:"size:64;not null"`
	PlayerUID          string        `gorm:"size:64;not null;index:idx_platform_account_profiles_player_uid"`
	Nickname           string        `gorm:"size:255;not null"`
	Level              sql.NullInt64 `gorm:"type:bigint"`
	IsPrimary          bool          `gorm:"not null;default:false"`
	SourceUpdatedAt    sql.NullTime  `gorm:"type:datetime(3)"`
	CreatedAt          time.Time     `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	UpdatedAt          time.Time     `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`

	Binding PlatformAccountBinding `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:BindingID;references:ID"`
}

func (PlatformAccountProfile) TableName() string {
	return "platform_account_profiles"
}

// ConsumerGrant records whether a named consumer may operate on a binding.
type ConsumerGrant struct {
	ID        uint64              `gorm:"primaryKey"`
	BindingID uint64              `gorm:"not null;uniqueIndex:uk_consumer_grants_binding_consumer,priority:1;index:idx_consumer_grants_binding_id"`
	Consumer  string              `gorm:"size:64;not null;uniqueIndex:uk_consumer_grants_binding_consumer,priority:2"`
	Status    ConsumerGrantStatus `gorm:"size:32;not null;default:'active';index:idx_consumer_grants_status"`
	GrantedBy sql.NullInt64       `gorm:"type:bigint unsigned;index:idx_consumer_grants_granted_by"`
	GrantedAt time.Time           `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	RevokedAt sql.NullTime        `gorm:"type:datetime(3)"`
	CreatedAt time.Time           `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`
	UpdatedAt time.Time           `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`

	Binding PlatformAccountBinding `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;foreignKey:BindingID;references:ID"`
	Grantor *User                  `gorm:"constraint:OnUpdate:CASCADE,OnDelete:SET NULL;foreignKey:GrantedBy;references:ID"`
}

func (ConsumerGrant) TableName() string {
	return "consumer_grants"
}

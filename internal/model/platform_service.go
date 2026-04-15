package model

import "time"

// PlatformService stores the platform registry used to resolve downstream services.
type PlatformService struct {
	ID                   uint64 `gorm:"primaryKey"`
	PlatformKey          string `gorm:"size:64;not null;uniqueIndex"`
	DisplayName          string `gorm:"size:128;not null"`
	ServiceKey           string `gorm:"size:128;not null;uniqueIndex"`
	ServiceAudience      string `gorm:"size:128;not null"`
	DiscoveryType        string `gorm:"size:32;not null"`
	Endpoint             string `gorm:"size:255;not null"`
	Enabled              bool   `gorm:"not null;default:true"`
	SupportedActionsJSON string `gorm:"type:json;not null"`
	CredentialSchemaJSON string `gorm:"type:json;not null"`
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

func (PlatformService) TableName() string {
	return "platform_services"
}

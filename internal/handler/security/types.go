package security

import (
	"time"
)

// TwoFactorSetupData holds temporary 2FA setup information
type TwoFactorSetupData struct {
	Secret      string    `json:"secret"`
	BackupCodes []string  `json:"backup_codes"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

package email

import (
	"fmt"
	"time"
)

// TemplateData defines the interface for email template data
type TemplateData interface {
	Validate() error
}

// EmailVerificationData holds data for email verification template
type EmailVerificationData struct {
	VerifyURL string
	Token     string
}

// Validate validates email verification data
func (d *EmailVerificationData) Validate() error {
	if d.VerifyURL == "" {
		return fmt.Errorf("verify URL is required")
	}
	if d.Token == "" {
		return fmt.Errorf("token is required")
	}
	return nil
}

// PasswordResetData holds data for password reset template
type PasswordResetData struct {
	ResetURL string
}

// Validate validates password reset data
func (d *PasswordResetData) Validate() error {
	if d.ResetURL == "" {
		return fmt.Errorf("reset URL is required")
	}
	return nil
}

// PasswordChangedData holds data for password changed template
type PasswordChangedData struct {
	Timestamp string
}

// Validate validates password changed data
func (d *PasswordChangedData) Validate() error {
	if d.Timestamp == "" {
		d.Timestamp = time.Now().Format("2006-01-02 15:04:05 MST")
	}
	return nil
}

// NewDeviceLoginData holds data for new device login template
type NewDeviceLoginData struct {
	DeviceName string
	Location   string
	IP         string
	Timestamp  string
}

// Validate validates new device login data
func (d *NewDeviceLoginData) Validate() error {
	if d.DeviceName == "" {
		return fmt.Errorf("device name is required")
	}
	if d.IP == "" {
		return fmt.Errorf("IP address is required")
	}
	if d.Timestamp == "" {
		d.Timestamp = time.Now().Format("2006-01-02 15:04:05 MST")
	}
	if d.Location == "" {
		d.Location = "Unknown"
	}
	return nil
}

// TwoFactorBackupCodesData holds data for 2FA backup codes template
type TwoFactorBackupCodesData struct {
	BackupCodes []string
}

// Validate validates 2FA backup codes data
func (d *TwoFactorBackupCodesData) Validate() error {
	if len(d.BackupCodes) == 0 {
		return fmt.Errorf("backup codes are required")
	}
	return nil
}

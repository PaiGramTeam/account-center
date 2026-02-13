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

// SuspiciousLoginData holds data for suspicious login alert template
type SuspiciousLoginData struct {
	DeviceName      string
	DeviceType      string
	Location        string
	IP              string
	Timestamp       string
	SuspicionLevel  string // "Low", "Medium", "High"
	SuspicionReason string
	SuspicionColor  string // HTML color code
	SecurityURL     string // URL to account security settings
}

// Validate validates suspicious login data
func (d *SuspiciousLoginData) Validate() error {
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
	if d.DeviceType == "" {
		d.DeviceType = "Unknown"
	}
	if d.SuspicionLevel == "" {
		d.SuspicionLevel = "Medium"
	}
	if d.SuspicionReason == "" {
		d.SuspicionReason = "Unusual login activity detected"
	}
	// Set color based on suspicion level
	if d.SuspicionColor == "" {
		switch d.SuspicionLevel {
		case "High":
			d.SuspicionColor = "#d32f2f" // Red
		case "Medium":
			d.SuspicionColor = "#f57c00" // Orange
		case "Low":
			d.SuspicionColor = "#fbc02d" // Yellow
		default:
			d.SuspicionColor = "#757575" // Gray
		}
	}
	if d.SecurityURL == "" {
		return fmt.Errorf("security URL is required")
	}
	return nil
}

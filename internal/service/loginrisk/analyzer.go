package loginrisk

import (
	"fmt"
	"time"

	"gorm.io/gorm"

	"paigram/internal/model"
)

// SuspicionLevel indicates how suspicious a login attempt is
type SuspicionLevel int

const (
	SuspicionNone SuspicionLevel = iota
	SuspicionLow
	SuspicionMedium
	SuspicionHigh
)

func (s SuspicionLevel) String() string {
	switch s {
	case SuspicionNone:
		return "none"
	case SuspicionLow:
		return "low"
	case SuspicionMedium:
		return "medium"
	case SuspicionHigh:
		return "high"
	default:
		return "unknown"
	}
}

// LoginAnalysis contains the result of analyzing a login attempt
type LoginAnalysis struct {
	Level         SuspicionLevel
	Reasons       []string
	IsNewDevice   bool
	IsNewIP       bool
	IsNewLocation bool
}

// IsSuspicious returns true if the login is suspicious
func (a *LoginAnalysis) IsSuspicious() bool {
	return a.Level >= SuspicionMedium
}

// Analyzer detects suspicious login patterns
type Analyzer struct {
	db *gorm.DB
}

// NewAnalyzer creates a new login analyzer
func NewAnalyzer(db *gorm.DB) *Analyzer {
	return &Analyzer{db: db}
}

// AnalyzeLogin analyzes a login attempt for suspicious activity
func (a *Analyzer) AnalyzeLogin(userID uint64, deviceID, ip, location string) (*LoginAnalysis, error) {
	analysis := &LoginAnalysis{
		Level:   SuspicionNone,
		Reasons: make([]string, 0),
	}

	// Get user's login history (last 30 days)
	var recentLogins []model.LoginLog
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	if err := a.db.Where("user_id = ? AND created_at > ? AND status = ?", userID, thirtyDaysAgo, "success").
		Order("created_at DESC").
		Limit(50).
		Find(&recentLogins).Error; err != nil {
		return nil, fmt.Errorf("query login history: %w", err)
	}

	// Check if this is the first login ever
	if len(recentLogins) == 0 {
		analysis.Level = SuspicionNone
		analysis.Reasons = append(analysis.Reasons, "first login")
		return analysis, nil
	}

	// Check for new device
	knownDevices := make(map[string]bool)
	for _, log := range recentLogins {
		if log.Device != "" {
			knownDevices[log.Device] = true
		}
	}

	// Get device info
	var device model.UserDevice
	if err := a.db.Where("device_id = ?", deviceID).First(&device).Error; err == nil {
		if _, exists := knownDevices[device.DeviceName]; !exists {
			analysis.IsNewDevice = true
			analysis.Level = SuspicionLow
			analysis.Reasons = append(analysis.Reasons, fmt.Sprintf("new device: %s", device.DeviceName))
		}
	}

	// Check for new IP
	knownIPs := make(map[string]bool)
	for _, log := range recentLogins {
		if log.IP != "" {
			knownIPs[log.IP] = true
		}
	}

	if _, exists := knownIPs[ip]; !exists {
		analysis.IsNewIP = true
		if analysis.Level < SuspicionLow {
			analysis.Level = SuspicionLow
		}
		analysis.Reasons = append(analysis.Reasons, fmt.Sprintf("new IP: %s", ip))
	}

	// Check for new location
	knownLocations := make(map[string]bool)
	for _, log := range recentLogins {
		if log.Location != "" {
			knownLocations[log.Location] = true
		}
	}

	if location != "" {
		if _, exists := knownLocations[location]; !exists {
			analysis.IsNewLocation = true
			if analysis.Level < SuspicionMedium {
				analysis.Level = SuspicionMedium
			}
			analysis.Reasons = append(analysis.Reasons, fmt.Sprintf("new location: %s", location))
		}
	}

	// Check for unusual time pattern
	lastLogin := recentLogins[0]
	timeSinceLastLogin := time.Since(lastLogin.CreatedAt)

	// If last login was very recent (< 1 minute), might be suspicious
	if timeSinceLastLogin < 1*time.Minute && (analysis.IsNewIP || analysis.IsNewDevice) {
		analysis.Level = SuspicionHigh
		analysis.Reasons = append(analysis.Reasons, "rapid login from new location/device")
	}

	// If new device + new location, elevate to high
	if analysis.IsNewDevice && analysis.IsNewLocation {
		analysis.Level = SuspicionHigh
	}

	return analysis, nil
}

// GetRecentSuspiciousLogins returns recent suspicious login attempts for a user
func (a *Analyzer) GetRecentSuspiciousLogins(userID uint64, days int) ([]model.LoginLog, error) {
	var logs []model.LoginLog
	since := time.Now().AddDate(0, 0, -days)

	// This is a simplified version - in a real implementation,
	// you'd store the suspicion level in the database
	if err := a.db.Where("user_id = ? AND created_at > ?", userID, since).
		Order("created_at DESC").
		Find(&logs).Error; err != nil {
		return nil, err
	}

	return logs, nil
}

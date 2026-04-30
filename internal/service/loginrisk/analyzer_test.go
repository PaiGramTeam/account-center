package loginrisk

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"paigram/internal/model"
)

func setupAnalyzerTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.LoginLog{}, &model.UserDevice{}))
	// Wipe rows from any earlier test that ran against the shared in-memory DB.
	require.NoError(t, db.Exec("DELETE FROM login_logs").Error)
	require.NoError(t, db.Exec("DELETE FROM user_devices").Error)
	return db
}

func insertLoginLog(t *testing.T, db *gorm.DB, userID uint64, device, ip, location string, when time.Time) {
	t.Helper()
	row := model.LoginLog{
		UserID:    userID,
		LoginType: model.LoginTypeEmail,
		Device:    device,
		IP:        ip,
		Location:  location,
		Status:    "success",
		CreatedAt: when,
	}
	require.NoError(t, db.Create(&row).Error)
}

func TestAnalyzeLoginFirstLogin(t *testing.T) {
	db := setupAnalyzerTestDB(t)
	a := NewAnalyzer(db)

	got, err := a.AnalyzeLogin(1, "device-1", "1.2.3.4", "City, Country")
	require.NoError(t, err)
	require.Equal(t, SuspicionNone, got.Level)
	require.Equal(t, []string{"first login"}, got.Reasons)
	require.False(t, got.IsNewDevice)
	require.False(t, got.IsNewIP)
	require.False(t, got.IsNewLocation)
}

func TestAnalyzeLoginAllKnown(t *testing.T) {
	db := setupAnalyzerTestDB(t)
	a := NewAnalyzer(db)

	require.NoError(t, db.Create(&model.UserDevice{UserID: 1, DeviceID: "dev-1", DeviceName: "Laptop", LastActiveAt: time.Now()}).Error)
	insertLoginLog(t, db, 1, "Laptop", "1.2.3.4", "Tokyo, Japan", time.Now().Add(-time.Hour))

	got, err := a.AnalyzeLogin(1, "dev-1", "1.2.3.4", "Tokyo, Japan")
	require.NoError(t, err)
	require.Equal(t, SuspicionNone, got.Level)
	require.False(t, got.IsNewDevice)
	require.False(t, got.IsNewIP)
	require.False(t, got.IsNewLocation)
}

func TestAnalyzeLoginNewIPOnly(t *testing.T) {
	db := setupAnalyzerTestDB(t)
	a := NewAnalyzer(db)

	require.NoError(t, db.Create(&model.UserDevice{UserID: 1, DeviceID: "dev-1", DeviceName: "Laptop", LastActiveAt: time.Now()}).Error)
	insertLoginLog(t, db, 1, "Laptop", "1.2.3.4", "Tokyo, Japan", time.Now().Add(-time.Hour))

	got, err := a.AnalyzeLogin(1, "dev-1", "9.9.9.9", "Tokyo, Japan")
	require.NoError(t, err)
	require.Equal(t, SuspicionLow, got.Level)
	require.True(t, got.IsNewIP)
	require.False(t, got.IsNewDevice)
	require.False(t, got.IsNewLocation)
	hasNewIP := false
	for _, r := range got.Reasons {
		if len(r) >= len("new IP") && r[:len("new IP")] == "new IP" {
			hasNewIP = true
		}
	}
	require.True(t, hasNewIP, "expected a 'new IP' reason, got %v", got.Reasons)
}

func TestAnalyzeLoginNewDeviceOnly(t *testing.T) {
	db := setupAnalyzerTestDB(t)
	a := NewAnalyzer(db)

	require.NoError(t, db.Create(&model.UserDevice{UserID: 1, DeviceID: "dev-2", DeviceName: "Phone", LastActiveAt: time.Now()}).Error)
	insertLoginLog(t, db, 1, "Laptop", "1.2.3.4", "Tokyo, Japan", time.Now().Add(-time.Hour))

	got, err := a.AnalyzeLogin(1, "dev-2", "1.2.3.4", "Tokyo, Japan")
	require.NoError(t, err)
	require.Equal(t, SuspicionLow, got.Level)
	require.True(t, got.IsNewDevice)
	require.False(t, got.IsNewIP)
	require.False(t, got.IsNewLocation)
}

func TestAnalyzeLoginNewLocationElevatesToMedium(t *testing.T) {
	db := setupAnalyzerTestDB(t)
	a := NewAnalyzer(db)

	require.NoError(t, db.Create(&model.UserDevice{UserID: 1, DeviceID: "dev-1", DeviceName: "Laptop", LastActiveAt: time.Now()}).Error)
	insertLoginLog(t, db, 1, "Laptop", "1.2.3.4", "Tokyo, Japan", time.Now().Add(-time.Hour))

	got, err := a.AnalyzeLogin(1, "dev-1", "1.2.3.4", "Berlin, Germany")
	require.NoError(t, err)
	require.Equal(t, SuspicionMedium, got.Level)
	require.True(t, got.IsNewLocation)
	require.False(t, got.IsNewDevice)
	require.False(t, got.IsNewIP)
}

func TestAnalyzeLoginNewDeviceAndNewLocationElevatesToHigh(t *testing.T) {
	db := setupAnalyzerTestDB(t)
	a := NewAnalyzer(db)

	require.NoError(t, db.Create(&model.UserDevice{UserID: 1, DeviceID: "dev-2", DeviceName: "Phone", LastActiveAt: time.Now()}).Error)
	insertLoginLog(t, db, 1, "Laptop", "1.2.3.4", "Tokyo, Japan", time.Now().Add(-time.Hour))

	got, err := a.AnalyzeLogin(1, "dev-2", "1.2.3.4", "Berlin, Germany")
	require.NoError(t, err)
	require.Equal(t, SuspicionHigh, got.Level)
	require.True(t, got.IsNewDevice)
	require.True(t, got.IsNewLocation)
}

func TestAnalyzeLoginRapidNewIPElevatesToHigh(t *testing.T) {
	db := setupAnalyzerTestDB(t)
	a := NewAnalyzer(db)

	require.NoError(t, db.Create(&model.UserDevice{UserID: 1, DeviceID: "dev-1", DeviceName: "Laptop", LastActiveAt: time.Now()}).Error)
	// Last login 30 seconds ago - within the 1-minute rapid-login window.
	insertLoginLog(t, db, 1, "Laptop", "1.2.3.4", "Tokyo, Japan", time.Now().Add(-30*time.Second))

	got, err := a.AnalyzeLogin(1, "dev-1", "9.9.9.9", "Tokyo, Japan")
	require.NoError(t, err)
	require.Equal(t, SuspicionHigh, got.Level)
	require.True(t, got.IsNewIP)
	rapidReasonFound := false
	for _, r := range got.Reasons {
		if r == "rapid login from new location/device" {
			rapidReasonFound = true
			break
		}
	}
	require.True(t, rapidReasonFound, "expected 'rapid login from new location/device' reason, got %v", got.Reasons)
}

func TestAnalyzeLoginEmptyLocationDoesNotTriggerLocationBranch(t *testing.T) {
	db := setupAnalyzerTestDB(t)
	a := NewAnalyzer(db)

	require.NoError(t, db.Create(&model.UserDevice{UserID: 1, DeviceID: "dev-1", DeviceName: "Laptop", LastActiveAt: time.Now()}).Error)
	insertLoginLog(t, db, 1, "Laptop", "1.2.3.4", "Tokyo, Japan", time.Now().Add(-time.Hour))

	got, err := a.AnalyzeLogin(1, "dev-1", "1.2.3.4", "")
	require.NoError(t, err)
	require.False(t, got.IsNewLocation)
	for _, r := range got.Reasons {
		require.NotContains(t, r, "new location")
	}
}

func TestSuspicionLevelString(t *testing.T) {
	require.Equal(t, "none", SuspicionNone.String())
	require.Equal(t, "low", SuspicionLow.String())
	require.Equal(t, "medium", SuspicionMedium.String())
	require.Equal(t, "high", SuspicionHigh.String())
	require.Equal(t, "unknown", SuspicionLevel(99).String())
}

func TestLoginAnalysisIsSuspicious(t *testing.T) {
	require.False(t, (&LoginAnalysis{Level: SuspicionNone}).IsSuspicious())
	require.False(t, (&LoginAnalysis{Level: SuspicionLow}).IsSuspicious())
	require.True(t, (&LoginAnalysis{Level: SuspicionMedium}).IsSuspicious())
	require.True(t, (&LoginAnalysis{Level: SuspicionHigh}).IsSuspicious())
}

func TestGetRecentSuspiciousLoginsRespectsDaysAndOrder(t *testing.T) {
	db := setupAnalyzerTestDB(t)
	a := NewAnalyzer(db)

	now := time.Now()
	insertLoginLog(t, db, 1, "Laptop", "1.1.1.1", "A", now.Add(-1*time.Hour))
	insertLoginLog(t, db, 1, "Laptop", "2.2.2.2", "A", now.Add(-2*time.Hour))
	insertLoginLog(t, db, 1, "Laptop", "3.3.3.3", "A", now.Add(-10*24*time.Hour)) // outside 7-day window

	logs, err := a.GetRecentSuspiciousLogins(1, 7)
	require.NoError(t, err)
	require.Len(t, logs, 2)
	require.Equal(t, "1.1.1.1", logs[0].IP) // most recent first
	require.Equal(t, "2.2.2.2", logs[1].IP)
}

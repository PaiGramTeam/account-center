package me

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"paigram/internal/model"
	"paigram/internal/sessioncache"
)

func setupSessionServiceSQLiteDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.UserSession{}, &model.UserDevice{}))
	return db
}

func TestSessionServiceListSessionsMarksCurrentAndLoadsDevice(t *testing.T) {
	db := setupMeServiceTestDB(t)
	service := NewSessionService(db, sessioncache.NewNoopStore())
	user := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&user).Error)
	accessToken := "current-access-token"
	currentHash := hashBearerToken(accessToken)
	now := time.Now().UTC()
	session := model.UserSession{
		UserID:           user.ID,
		AccessTokenHash:  currentHash,
		RefreshTokenHash: "refresh-hash-1",
		AccessExpiry:     now.Add(time.Hour),
		RefreshExpiry:    now.Add(24 * time.Hour),
		UserAgent:        "Mozilla/5.0",
		ClientIP:         "127.0.0.1",
		CreatedAt:        now.Add(-time.Minute),
	}
	require.NoError(t, db.Create(&session).Error)
	device := model.UserDevice{UserID: user.ID, DeviceID: buildDeviceID(session.UserAgent, session.ClientIP), DeviceName: "Laptop", DeviceType: "desktop", Location: "Localhost", LastActiveAt: now}
	require.NoError(t, db.Create(&device).Error)

	views, total, err := service.ListSessions(context.Background(), user.ID, 1, 20, accessToken)
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Len(t, views, 1)
	assert.True(t, views[0].IsCurrent)
	assert.Equal(t, "Laptop", views[0].DeviceName)
	assert.Equal(t, "Localhost", views[0].Location)
}

func TestSessionServiceListSessionsPaginatesAndCountsAllActiveSessions(t *testing.T) {
	db := setupMeServiceTestDB(t)
	service := NewSessionService(db, sessioncache.NewNoopStore())
	user := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	otherUser := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&user).Error)
	require.NoError(t, db.Create(&otherUser).Error)

	base := time.Now().UTC().Add(-10 * time.Minute)
	for i := 0; i < 3; i++ {
		session := model.UserSession{
			UserID:           user.ID,
			AccessTokenHash:  hashBearerToken(time.Now().UTC().Add(time.Duration(i) * time.Second).String()),
			RefreshTokenHash: hashBearerToken(time.Now().UTC().Add(time.Duration(i+10) * time.Second).String()),
			AccessExpiry:     base.Add(24 * time.Hour),
			RefreshExpiry:    base.Add(48 * time.Hour),
			UserAgent:        "Mozilla/5.0",
			ClientIP:         "127.0.0.1",
			CreatedAt:        base.Add(time.Duration(i) * time.Minute),
		}
		require.NoError(t, db.Create(&session).Error)
	}
	require.NoError(t, db.Create(&model.UserSession{
		UserID:           user.ID,
		AccessTokenHash:  hashBearerToken("revoked-access"),
		RefreshTokenHash: hashBearerToken("revoked-refresh"),
		AccessExpiry:     base.Add(24 * time.Hour),
		RefreshExpiry:    base.Add(48 * time.Hour),
		RevokedAt:        sql.NullTime{Time: base.Add(5 * time.Minute), Valid: true},
	}).Error)
	require.NoError(t, db.Create(&model.UserSession{
		UserID:           otherUser.ID,
		AccessTokenHash:  hashBearerToken("other-access"),
		RefreshTokenHash: hashBearerToken("other-refresh"),
		AccessExpiry:     base.Add(24 * time.Hour),
		RefreshExpiry:    base.Add(48 * time.Hour),
		CreatedAt:        base.Add(6 * time.Minute),
	}).Error)

	views, total, err := service.ListSessions(context.Background(), user.ID, 2, 2, "")
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
	require.Len(t, views, 1)
	assert.False(t, views[0].IsCurrent)
	assert.WithinDuration(t, base, views[0].CreatedAt, time.Second)
}

func TestSessionServiceListSessionsUsesStableOrderForEqualTimestamps(t *testing.T) {
	db := setupSessionServiceSQLiteDB(t)
	service := NewSessionService(db, sessioncache.NewNoopStore())

	createdAt := time.Now().UTC().Truncate(time.Millisecond)
	const userID uint64 = 2002
	sessions := make([]model.UserSession, 0, 3)
	for i := 0; i < 3; i++ {
		session := model.UserSession{
			UserID:           userID,
			AccessTokenHash:  hashBearerToken("stable-access-" + time.Duration(i).String()),
			RefreshTokenHash: hashBearerToken("stable-refresh-" + time.Duration(i).String()),
			AccessExpiry:     createdAt.Add(24 * time.Hour),
			RefreshExpiry:    createdAt.Add(48 * time.Hour),
			UserAgent:        "Mozilla/5.0",
			ClientIP:         "127.0.0.1",
			CreatedAt:        createdAt,
		}
		require.NoError(t, db.Create(&session).Error)
		sessions = append(sessions, session)
	}

	firstPage, total, err := service.ListSessions(context.Background(), userID, 1, 2, "")
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
	require.Len(t, firstPage, 2)
	assert.Equal(t, sessions[2].ID, firstPage[0].ID)
	assert.Equal(t, sessions[1].ID, firstPage[1].ID)

	secondPage, total, err := service.ListSessions(context.Background(), userID, 2, 2, "")
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
	require.Len(t, secondPage, 1)
	assert.Equal(t, sessions[0].ID, secondPage[0].ID)
}

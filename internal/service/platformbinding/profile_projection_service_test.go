package platformbinding

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/model"
)

func TestProfileProjectionServiceSyncProfilesUpsertsAndUpdatesPrimary(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewProfileProjectionService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: "cn:profile",
		PlatformServiceKey: "mihomo",
		DisplayName:        "Profile Sync",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)

	syncedAt := time.Now().UTC()
	profiles, err := service.SyncProfiles(SyncProfilesInput{
		BindingID: binding.ID,
		SyncedAt:  syncedAt,
		Profiles: []ProfileProjectionInput{
			{
				PlatformProfileKey: "gs:1",
				GameBiz:            "hk4e_cn",
				Region:             "cn_gf01",
				PlayerUID:          "10001",
				Nickname:           "Traveler",
				Level:              sql.NullInt64{Int64: 60, Valid: true},
				IsPrimary:          true,
				SourceUpdatedAt:    sql.NullTime{Time: syncedAt, Valid: true},
			},
			{
				PlatformProfileKey: "gs:2",
				GameBiz:            "hk4e_global",
				Region:             "os_usa",
				PlayerUID:          "20002",
				Nickname:           "Aether",
				Level:              sql.NullInt64{Int64: 55, Valid: true},
				IsPrimary:          false,
				SourceUpdatedAt:    sql.NullTime{Time: syncedAt, Valid: true},
			},
		},
	})
	require.NoError(t, err)
	require.Len(t, profiles, 2)
	assert.True(t, profiles[0].IsPrimary)

	resyncedAt := syncedAt.Add(time.Minute)
	profiles, err = service.SyncProfiles(SyncProfilesInput{
		BindingID: binding.ID,
		SyncedAt:  resyncedAt,
		Profiles: []ProfileProjectionInput{
			{
				PlatformProfileKey: "gs:1",
				GameBiz:            "hk4e_cn",
				Region:             "cn_gf01",
				PlayerUID:          "10001",
				Nickname:           "Traveler Updated",
				Level:              sql.NullInt64{Int64: 60, Valid: true},
				IsPrimary:          false,
				SourceUpdatedAt:    sql.NullTime{Time: resyncedAt, Valid: true},
			},
			{
				PlatformProfileKey: "gs:2",
				GameBiz:            "hk4e_global",
				Region:             "os_usa",
				PlayerUID:          "20002",
				Nickname:           "Aether Prime",
				Level:              sql.NullInt64{Int64: 56, Valid: true},
				IsPrimary:          true,
				SourceUpdatedAt:    sql.NullTime{Time: resyncedAt, Valid: true},
			},
		},
	})
	require.NoError(t, err)
	require.Len(t, profiles, 2)

	var bindingAfter model.PlatformAccountBinding
	require.NoError(t, db.First(&bindingAfter, binding.ID).Error)
	assert.True(t, bindingAfter.PrimaryProfileID.Valid)
	assert.WithinDuration(t, resyncedAt, bindingAfter.LastSyncedAt.Time, time.Millisecond)

	var primary model.PlatformAccountProfile
	require.NoError(t, db.First(&primary, bindingAfter.PrimaryProfileID.Int64).Error)
	assert.Equal(t, "gs:2", primary.PlatformProfileKey)
	assert.Equal(t, "Aether Prime", primary.Nickname)

	var oldPrimary model.PlatformAccountProfile
	require.NoError(t, db.Where("binding_id = ? AND platform_profile_key = ?", binding.ID, "gs:1").First(&oldPrimary).Error)
	assert.False(t, oldPrimary.IsPrimary)
	assert.Equal(t, "Traveler Updated", oldPrimary.Nickname)
}

func TestProfileProjectionServiceRejectsMultiplePrimaryProfiles(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewProfileProjectionService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: "cn:multi-primary",
		PlatformServiceKey: "mihomo",
		DisplayName:        "Invalid Primary",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)

	_, err := service.SyncProfiles(SyncProfilesInput{
		BindingID: binding.ID,
		Profiles: []ProfileProjectionInput{
			{PlatformProfileKey: "gs:1", GameBiz: "hk4e_cn", Region: "cn_gf01", PlayerUID: "10001", Nickname: "Traveler", IsPrimary: true},
			{PlatformProfileKey: "gs:2", GameBiz: "hk4e_global", Region: "os_usa", PlayerUID: "20002", Nickname: "Aether", IsPrimary: true},
		},
	})
	require.ErrorIs(t, err, ErrMultiplePrimaryProfiles)
}

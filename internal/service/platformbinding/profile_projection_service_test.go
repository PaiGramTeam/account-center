package platformbinding

import (
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

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
		ExternalAccountKey: ns("cn:profile"),
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
	assert.False(t, bindingAfter.LastSyncedAt.Valid)

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
		ExternalAccountKey: ns("cn:multi-primary"),
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

func TestListProfilesPaginatesResults(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewProfileProjectionService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: ns("cn:profiles"),
		PlatformServiceKey: "mihomo",
		DisplayName:        "Profile List",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)

	for i := 0; i < 3; i++ {
		require.NoError(t, db.Create(&model.PlatformAccountProfile{
			BindingID:          binding.ID,
			PlatformProfileKey: fmt.Sprintf("gs:%d", i),
			GameBiz:            "hk4e_cn",
			Region:             "cn_gf01",
			PlayerUID:          fmt.Sprintf("1000%d", i),
			Nickname:           fmt.Sprintf("Traveler %d", i),
			IsPrimary:          i == 0,
		}).Error)
	}

	items, total, err := service.ListProfiles(binding.ID, ListParams{Page: 2, PageSize: 1})
	require.NoError(t, err)
	assert.Equal(t, int64(3), total)
	require.Len(t, items, 1)

	ownerItems, ownerTotal, err := service.ListProfilesForOwner(owner.ID, binding.ID, ListParams{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Equal(t, int64(3), ownerTotal)
	require.Len(t, ownerItems, 2)
}

func TestProfileProjectionServiceSyncProfilesDoesNotClobberRuntimeSummaryFields(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	projectionService := NewProfileProjectionService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding := model.PlatformAccountBinding{
		OwnerUserID:         owner.ID,
		Platform:            "mihomo",
		ExternalAccountKey:  ns("cn:stale-before-sync"),
		PlatformServiceKey:  "mihomo",
		DisplayName:         "Profile Sync Race",
		Status:              model.PlatformAccountBindingStatusPendingBind,
		StatusReasonCode:    "pending_sync",
		StatusReasonMessage: "waiting",
	}
	require.NoError(t, db.Create(&binding).Error)

	var once sync.Once
	callbackName := "test:binding-save-runtime-summary"
	db.Callback().Update().Before("gorm:update").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement == nil || tx.Statement.Schema == nil || tx.Statement.Schema.Table != "platform_account_bindings" {
			return
		}
		once.Do(func() {
			err := tx.Exec(`
				UPDATE platform_account_bindings
				SET external_account_key = ?,
				    status = ?,
				    status_reason_code = ?,
				    last_validated_at = ?,
				    last_synced_at = ?
				WHERE id = ?
			`,
				"cn:runtime-summary-owned",
				model.PlatformAccountBindingStatusCredentialInvalid,
				"challenge_required",
				time.Date(2026, 4, 19, 12, 34, 56, 0, time.UTC),
				time.Date(2026, 4, 19, 13, 34, 56, 0, time.UTC),
				binding.ID,
			).Error
			require.NoError(t, err)
		})
	})
	defer db.Callback().Update().Remove(callbackName)

	profiles, err := projectionService.SyncProfiles(SyncProfilesInput{
		BindingID: binding.ID,
		SyncedAt:  time.Date(2026, 4, 19, 14, 0, 0, 0, time.UTC),
		Profiles: []ProfileProjectionInput{
			{
				PlatformProfileKey: "gs:runtime-owned",
				GameBiz:            "hk4e_cn",
				Region:             "cn_gf01",
				PlayerUID:          "10001",
				Nickname:           "Traveler",
				Level:              sql.NullInt64{Int64: 60, Valid: true},
				IsPrimary:          true,
			},
		},
	})
	require.NoError(t, err)
	require.Len(t, profiles, 1)

	bindingService := NewBindingService(db)
	updatedBinding, err := bindingService.GetBindingByID(binding.ID)
	require.NoError(t, err)
	require.True(t, updatedBinding.ExternalAccountKey.Valid)
	assert.Equal(t, "cn:runtime-summary-owned", updatedBinding.ExternalAccountKey.String)
	assert.Equal(t, model.PlatformAccountBindingStatusCredentialInvalid, updatedBinding.Status)
	assert.Equal(t, "challenge_required", updatedBinding.StatusReasonCode)
	assert.True(t, updatedBinding.LastValidatedAt.Valid)
	assert.Equal(t, int64(profiles[0].ID), updatedBinding.PrimaryProfileID.Int64)
	assert.True(t, updatedBinding.LastSyncedAt.Valid)
	assert.WithinDuration(t, time.Date(2026, 4, 19, 13, 34, 56, 0, time.UTC), updatedBinding.LastSyncedAt.Time, time.Millisecond)
}

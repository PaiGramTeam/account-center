package platformbinding

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"paigram/internal/model"
	"paigram/internal/testutil"
)

func setupPlatformBindingTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db := testutil.OpenMySQLTestDB(t, "platformbinding")
	for _, fileName := range []string{
		"000001_create_users_table.up.sql",
		"000011_create_roles_table.up.sql",
		"000013_create_user_roles_table.up.sql",
		"000034_add_primary_role_id_to_users.up.sql",
		"000035_create_platform_account_bindings_table.up.sql",
		"000036_create_platform_account_profiles_table.up.sql",
		"000037_create_consumer_grants_table.up.sql",
	} {
		require.NoError(t, db.Exec(readPlatformBindingMigration(t, fileName)).Error)
	}

	return db
}

func TestCreateBindingRejectsDuplicateExternalAccount(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewBindingService(db)
	ownerA := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	ownerB := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&ownerA).Error)
	require.NoError(t, db.Create(&ownerB).Error)

	first, err := service.CreateBinding(CreateBindingInput{
		OwnerUserID:        ownerA.ID,
		Platform:           "mihomo",
		ExternalAccountKey: "cn:123",
		PlatformServiceKey: "mihomo",
		DisplayName:        "CN Main",
	})
	require.NoError(t, err)
	require.NotNil(t, first)

	second, err := service.CreateBinding(CreateBindingInput{
		OwnerUserID:        ownerB.ID,
		Platform:           "mihomo",
		ExternalAccountKey: "cn:123",
		PlatformServiceKey: "mihomo",
		DisplayName:        "Conflict",
	})
	require.ErrorIs(t, err, ErrBindingAlreadyOwned)
	assert.Nil(t, second)
}

func TestBindingServiceUpdatesStatusAndDeletesBinding(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewBindingService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)

	binding, err := service.CreateBinding(CreateBindingInput{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: "cn:456",
		PlatformServiceKey: "mihomo",
		DisplayName:        "CN Alt",
	})
	require.NoError(t, err)

	updated, err := service.UpdateBindingStatus(binding.ID, model.PlatformAccountBindingStatusDisabled)
	require.NoError(t, err)
	assert.Equal(t, model.PlatformAccountBindingStatusDisabled, updated.Status)

	deleted, err := service.DeleteBinding(binding.ID)
	require.NoError(t, err)
	assert.Equal(t, model.PlatformAccountBindingStatusDeleted, deleted.Status)
	assert.True(t, deleted.DeletedAt.Valid)

	_, err = service.GetBindingByID(binding.ID)
	require.ErrorIs(t, err, ErrBindingNotFound)

	var persisted model.PlatformAccountBinding
	require.NoError(t, db.Unscoped().First(&persisted, binding.ID).Error)
	assert.Equal(t, model.PlatformAccountBindingStatusDeleted, persisted.Status)
	assert.True(t, persisted.DeletedAt.Valid)
}

func TestCreateBindingReturnsExistingBindingForDuplicateOwnedBySameUser(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewBindingService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)

	first, err := service.CreateBinding(CreateBindingInput{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: "cn:same-owner",
		PlatformServiceKey: "mihomo",
		DisplayName:        "CN Main",
	})
	require.NoError(t, err)

	second, err := service.CreateBinding(CreateBindingInput{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: "cn:same-owner",
		PlatformServiceKey: "mihomo",
		DisplayName:        "CN Main",
	})
	require.NoError(t, err)
	require.NotNil(t, second)
	assert.Equal(t, first.ID, second.ID)
}

func TestBindingServiceUpdatesOwnerEditableFields(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewBindingService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)

	binding, err := service.CreateBinding(CreateBindingInput{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: "cn:editable",
		PlatformServiceKey: "mihomo-old",
		DisplayName:        "Old Name",
	})
	require.NoError(t, err)

	updated, err := service.UpdateBindingForOwner(owner.ID, binding.ID, UpdateBindingInput{
		DisplayName:        ptrString("New Name"),
		PlatformServiceKey: ptrString("mihomo-new"),
	})
	require.NoError(t, err)
	assert.Equal(t, "New Name", updated.DisplayName)
	assert.Equal(t, "mihomo-new", updated.PlatformServiceKey)
}

func TestUpsertGrantIsIdempotentAndRevokeMarksGrantRevoked(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	grantService := NewGrantService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	grantorA := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	grantorB := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	require.NoError(t, db.Create(&grantorA).Error)
	require.NoError(t, db.Create(&grantorB).Error)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: "cn:123",
		PlatformServiceKey: "mihomo",
		DisplayName:        "CN Main",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)

	grant, created, err := grantService.UpsertGrant(UpsertGrantInput{
		BindingID: binding.ID,
		Consumer:  "paigram-bot",
		GrantedBy: sql.NullInt64{Int64: int64(grantorA.ID), Valid: true},
		GrantedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	assert.True(t, created)
	assert.Equal(t, model.ConsumerGrantStatusActive, grant.Status)

	grantAgain, created, err := grantService.UpsertGrant(UpsertGrantInput{
		BindingID: binding.ID,
		Consumer:  "paigram-bot",
		GrantedBy: sql.NullInt64{Int64: int64(grantorB.ID), Valid: true},
		GrantedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	assert.False(t, created)
	assert.Equal(t, grant.ID, grantAgain.ID)
	assert.Equal(t, model.ConsumerGrantStatusActive, grantAgain.Status)
	assert.Equal(t, int64(grantorB.ID), grantAgain.GrantedBy.Int64)

	revoked, err := grantService.RevokeGrant(RevokeGrantInput{
		BindingID: binding.ID,
		Consumer:  "paigram-bot",
		RevokedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	assert.Equal(t, model.ConsumerGrantStatusRevoked, revoked.Status)
	assert.True(t, revoked.RevokedAt.Valid)

	revokedAgain, err := grantService.RevokeGrant(RevokeGrantInput{
		BindingID: binding.ID,
		Consumer:  "paigram-bot",
		RevokedAt: time.Now().UTC().Add(time.Minute),
	})
	require.NoError(t, err)
	assert.Equal(t, revoked.ID, revokedAgain.ID)
	assert.Equal(t, model.ConsumerGrantStatusRevoked, revokedAgain.Status)
	assert.WithinDuration(t, revoked.RevokedAt.Time, revokedAgain.RevokedAt.Time, time.Millisecond)
}

func TestGrantServiceRejectsUnsupportedConsumer(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	grantService := NewGrantService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: "cn:unsupported",
		PlatformServiceKey: "mihomo",
		DisplayName:        "Unsupported",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)

	_, _, err := grantService.UpsertGrant(UpsertGrantInput{
		BindingID: binding.ID,
		Consumer:  "unknown-consumer",
	})
	require.ErrorIs(t, err, ErrConsumerNotSupported)

	_, err = grantService.RevokeGrant(RevokeGrantInput{
		BindingID: binding.ID,
		Consumer:  "unknown-consumer",
	})
	require.ErrorIs(t, err, ErrConsumerNotSupported)
}

func TestProfileProjectionServiceSetsPrimaryProfileForOwner(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewProfileProjectionService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: "cn:primary-profile",
		PlatformServiceKey: "mihomo",
		DisplayName:        "Primary Profile",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)
	profiles := []model.PlatformAccountProfile{
		{BindingID: binding.ID, PlatformProfileKey: "mihomo:10001", GameBiz: "hk4e_cn", Region: "cn_gf01", PlayerUID: "10001", Nickname: "Traveler", IsPrimary: true},
		{BindingID: binding.ID, PlatformProfileKey: "mihomo:10002", GameBiz: "hk4e_global", Region: "os_asia", PlayerUID: "10002", Nickname: "Lumine"},
	}
	require.NoError(t, db.Create(&profiles).Error)
	require.NoError(t, db.Model(&binding).Update("primary_profile_id", profiles[0].ID).Error)

	updated, err := service.SetPrimaryProfileForOwner(owner.ID, binding.ID, &profiles[1].ID)
	require.NoError(t, err)
	assert.True(t, updated.PrimaryProfileID.Valid)
	assert.Equal(t, int64(profiles[1].ID), updated.PrimaryProfileID.Int64)

	var primary model.PlatformAccountProfile
	require.NoError(t, db.First(&primary, profiles[1].ID).Error)
	assert.True(t, primary.IsPrimary)

	var previous model.PlatformAccountProfile
	require.NoError(t, db.First(&previous, profiles[0].ID).Error)
	assert.False(t, previous.IsPrimary)
}

func TestProfileProjectionServiceRejectsPrimaryProfileOutsideBinding(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewProfileProjectionService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: "cn:binding-a",
		PlatformServiceKey: "mihomo",
		DisplayName:        "Binding A",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	otherBinding := model.PlatformAccountBinding{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: "cn:binding-b",
		PlatformServiceKey: "mihomo",
		DisplayName:        "Binding B",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)
	require.NoError(t, db.Create(&otherBinding).Error)
	profile := model.PlatformAccountProfile{BindingID: otherBinding.ID, PlatformProfileKey: "mihomo:20001", GameBiz: "hk4e_cn", Region: "cn_gf01", PlayerUID: "20001", Nickname: "Other"}
	require.NoError(t, db.Create(&profile).Error)

	_, err := service.SetPrimaryProfileForOwner(owner.ID, binding.ID, &profile.ID)
	require.Error(t, err)
}

func ptrString(value string) *string {
	return &value
}

func readPlatformBindingMigration(t *testing.T, fileName string) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	require.True(t, ok)

	path := filepath.Join(filepath.Dir(currentFile), "..", "..", "..", "initialize", "migrate", "sql", fileName)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(content)
}

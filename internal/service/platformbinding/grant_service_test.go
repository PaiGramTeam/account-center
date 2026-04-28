package platformbinding

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/model"
)

func TestListGrantsPaginatesResults(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewGrantService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: ns("cn:grants"),
		PlatformServiceKey: "mihomo",
		DisplayName:        "Grant List",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)

	for _, consumer := range []string{ConsumerPaiGramBot, ConsumerPamgram, "mihomo.sync"} {
		require.NoError(t, db.Create(&model.ConsumerGrant{
			BindingID: binding.ID,
			Consumer:  consumer,
			Status:    model.ConsumerGrantStatusActive,
		}).Error)
	}

	items, total, err := service.ListGrants(binding.ID, ListParams{Page: 2, PageSize: 1})
	require.NoError(t, err)
	assert.Equal(t, int64(3), total)
	require.Len(t, items, 1)

	ownerItems, ownerTotal, err := service.ListGrantsForOwner(owner.ID, binding.ID, ListParams{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Equal(t, int64(3), ownerTotal)
	require.Len(t, ownerItems, 2)
}

func TestGrantServiceSupportsRegistryConsumers(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewGrantService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: ns("cn:grant-consumers"),
		PlatformServiceKey: "mihomo",
		DisplayName:        "Grant Consumers",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)

	for _, consumer := range []string{ConsumerPaiGramBot, ConsumerPamgram} {
		grant, created, err := service.UpsertGrant(UpsertGrantInput{
			BindingID: binding.ID,
			Consumer:  consumer,
			GrantedBy: sql.NullInt64{Int64: int64(owner.ID), Valid: true},
			GrantedAt: time.Now().UTC(),
		})
		require.NoError(t, err)
		assert.True(t, created)
		assert.Equal(t, consumer, grant.Consumer)
		assert.Equal(t, model.ConsumerGrantStatusActive, grant.Status)
		assert.False(t, grant.RevokedAt.Valid)
	}
}

func TestGrantServiceUpsertRejectsUnsupportedConsumer(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewGrantService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: ns("cn:grant-unsupported"),
		PlatformServiceKey: "mihomo",
		DisplayName:        "Grant Unsupported",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)

	grant, created, err := service.UpsertGrant(UpsertGrantInput{
		BindingID: binding.ID,
		Consumer:  "unsupported-consumer",
	})
	assert.ErrorIs(t, err, ErrConsumerNotSupported)
	assert.Nil(t, grant)
	assert.False(t, created)
}

func TestGrantServiceRevokeGrantIsIdempotentWhenGrantDoesNotExist(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewGrantService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: ns("cn:grant-revoke-idempotent"),
		PlatformServiceKey: "mihomo",
		DisplayName:        "Grant Revoke Idempotent",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)

	revokedAt := time.Now().UTC()
	grant, err := service.RevokeGrant(RevokeGrantInput{
		BindingID: binding.ID,
		Consumer:  ConsumerPaiGramBot,
		RevokedAt: revokedAt,
	})
	require.NoError(t, err)
	assert.Equal(t, binding.ID, grant.BindingID)
	assert.Equal(t, ConsumerPaiGramBot, grant.Consumer)
	assert.Equal(t, model.ConsumerGrantStatusRevoked, grant.Status)
	assert.True(t, grant.RevokedAt.Valid)
	assert.True(t, grant.RevokedAt.Time.Equal(revokedAt))

	var count int64
	require.NoError(t, db.Model(&model.ConsumerGrant{}).Where("binding_id = ? AND consumer = ?", binding.ID, ConsumerPaiGramBot).Count(&count).Error)
	assert.Zero(t, count)
}

func TestGrantServiceUpsertWritesUnifiedAuditEvent(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewGrantService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: ns("cn:grant-audit"),
		PlatformServiceKey: "mihomo",
		DisplayName:        "Grant Audit",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)

	_, _, err := service.UpsertGrant(UpsertGrantInput{
		BindingID: binding.ID,
		Consumer:  ConsumerPaiGramBot,
		GrantedBy: sql.NullInt64{Int64: int64(owner.ID), Valid: true},
		GrantedAt: time.Now().UTC(),
	})
	require.NoError(t, err)

	var event model.AuditEvent
	require.NoError(t, db.Where("category = ? AND action = ?", "platform_binding", "grant_change").Order("id DESC").First(&event).Error)
	assert.Equal(t, "binding", event.TargetType)
	assert.Equal(t, "success", event.Result)
	assert.Equal(t, int64(binding.ID), event.BindingID.Int64)
	metadata := requireGrantAuditMetadata(t, event.MetadataJSON)
	assert.Equal(t, ConsumerPaiGramBot, metadata["consumer"])
	assert.Equal(t, true, metadata["grant_enabled"])
}

func TestGrantServiceRevokeWritesAdminActorAttribution(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewGrantService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	admin := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	require.NoError(t, db.Create(&admin).Error)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: ns("cn:grant-revoke-audit"),
		PlatformServiceKey: "mihomo",
		DisplayName:        "Grant Revoke Audit",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)
	require.NoError(t, db.Create(&model.ConsumerGrant{
		BindingID: binding.ID,
		Consumer:  ConsumerPaiGramBot,
		Status:    model.ConsumerGrantStatusActive,
		GrantedBy: sql.NullInt64{Int64: int64(owner.ID), Valid: true},
		GrantedAt: time.Now().UTC(),
	}).Error)

	_, err := service.RevokeGrant(RevokeGrantInput{
		BindingID:   binding.ID,
		Consumer:    ConsumerPaiGramBot,
		RevokedAt:   time.Now().UTC(),
		ActorUserID: sql.NullInt64{Int64: int64(admin.ID), Valid: true},
	})
	require.NoError(t, err)

	var event model.AuditEvent
	require.NoError(t, db.Where("category = ? AND action = ?", "platform_binding", "grant_change").Order("id DESC").First(&event).Error)
	assert.Equal(t, "admin", event.ActorType)
	assert.True(t, event.ActorUserID.Valid)
	assert.Equal(t, int64(admin.ID), event.ActorUserID.Int64)
	metadata := requireGrantAuditMetadata(t, event.MetadataJSON)
	assert.Equal(t, ConsumerPaiGramBot, metadata["consumer"])
	assert.Equal(t, false, metadata["grant_enabled"])
	actor, ok := metadata["actor"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "admin", actor["type"])
}

func requireGrantAuditMetadata(t *testing.T, metadataJSON string) map[string]any {
	t.Helper()
	var metadata map[string]any
	require.NoError(t, json.Unmarshal([]byte(metadataJSON), &metadata))
	return metadata
}

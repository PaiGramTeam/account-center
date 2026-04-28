package platformbinding

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

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

func TestPlatformBindingServiceGroupWiresGrantInvalidator(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	platformService := &serviceGroupPlatformServiceStub{}

	group := NewServiceGroup(db, platformService)

	require.Same(t, platformService, group.GrantService.invalidator)
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
	assert.Equal(t, uint64(1), grant.TicketVersion)
	assert.True(t, grant.RevokedAt.Valid)
	assert.True(t, grant.RevokedAt.Time.Equal(revokedAt))
	assert.True(t, grant.LastInvalidatedAt.Valid)
	assert.True(t, grant.LastInvalidatedAt.Time.Equal(revokedAt))

	var count int64
	require.NoError(t, db.Model(&model.ConsumerGrant{}).Where("binding_id = ? AND consumer = ?", binding.ID, ConsumerPaiGramBot).Count(&count).Error)
	assert.Zero(t, count)
}

func TestGrantServiceRevokeGrantIncrementsTicketVersion(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewGrantService(db)
	binding := seedGrantServiceBinding(t, db, "cn:grant-version")
	revokedAt := time.Now().UTC()
	require.NoError(t, db.Create(&model.ConsumerGrant{
		BindingID:     binding.ID,
		Consumer:      ConsumerPaiGramBot,
		Status:        model.ConsumerGrantStatusActive,
		ScopesJSON:    "[]",
		TicketVersion: 1,
		GrantedAt:     time.Now().UTC(),
	}).Error)

	revoked, err := service.RevokeGrant(RevokeGrantInput{
		BindingID: binding.ID,
		Consumer:  ConsumerPaiGramBot,
		RevokedAt: revokedAt,
	})

	require.NoError(t, err)
	assert.Equal(t, model.ConsumerGrantStatusRevoked, revoked.Status)
	assert.Equal(t, uint64(2), revoked.TicketVersion)
	assert.True(t, revoked.RevokedAt.Valid)
	assert.True(t, revoked.LastInvalidatedAt.Valid)
	assert.True(t, revoked.LastInvalidatedAt.Time.Equal(revokedAt))
}

func TestGrantServiceRevokeGrantAlreadyRevokedDoesNotIncrementTicketVersion(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewGrantService(db)
	binding := seedGrantServiceBinding(t, db, "cn:grant-already-revoked")
	revokedAt := time.Now().UTC().Add(-time.Hour)
	require.NoError(t, db.Create(&model.ConsumerGrant{
		BindingID:         binding.ID,
		Consumer:          ConsumerPaiGramBot,
		Status:            model.ConsumerGrantStatusRevoked,
		ScopesJSON:        "[]",
		TicketVersion:     3,
		GrantedAt:         time.Now().UTC(),
		RevokedAt:         sql.NullTime{Time: revokedAt, Valid: true},
		LastInvalidatedAt: sql.NullTime{Time: revokedAt, Valid: true},
	}).Error)

	revoked, err := service.RevokeGrant(RevokeGrantInput{
		BindingID: binding.ID,
		Consumer:  ConsumerPaiGramBot,
		RevokedAt: time.Now().UTC(),
	})

	require.NoError(t, err)
	assert.Equal(t, model.ConsumerGrantStatusRevoked, revoked.Status)
	assert.Equal(t, uint64(3), revoked.TicketVersion)
	assert.True(t, revoked.LastInvalidatedAt.Valid)
	assert.True(t, revoked.LastInvalidatedAt.Time.Equal(revokedAt))
}

func TestGrantServiceUpsertGrantReactivationPreservesTicketVersion(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewGrantService(db)
	binding := seedGrantServiceBinding(t, db, "cn:grant-reactivate")
	require.NoError(t, db.Create(&model.ConsumerGrant{
		BindingID:         binding.ID,
		Consumer:          ConsumerPaiGramBot,
		Status:            model.ConsumerGrantStatusRevoked,
		ScopesJSON:        "[]",
		TicketVersion:     4,
		GrantedAt:         time.Now().UTC(),
		RevokedAt:         sql.NullTime{Time: time.Now().UTC(), Valid: true},
		LastInvalidatedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}).Error)

	grant, created, err := service.UpsertGrant(UpsertGrantInput{
		BindingID: binding.ID,
		Consumer:  ConsumerPaiGramBot,
		GrantedBy: sql.NullInt64{Int64: int64(binding.OwnerUserID), Valid: true},
		GrantedAt: time.Now().UTC(),
	})

	require.NoError(t, err)
	assert.False(t, created)
	assert.Equal(t, model.ConsumerGrantStatusActive, grant.Status)
	assert.False(t, grant.RevokedAt.Valid)
	assert.Equal(t, uint64(4), grant.TicketVersion)
}

func TestGrantServiceRevokeGrantInvalidatorFailureLeavesRetryableRevocation(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	invalidationErr := errors.New("platform down")
	service := NewGrantService(db, failingGrantInvalidator{err: invalidationErr})
	binding := seedGrantServiceBinding(t, db, "cn:grant-invalid-failure")
	require.NoError(t, db.Create(&model.ConsumerGrant{
		BindingID:     binding.ID,
		Consumer:      ConsumerPaiGramBot,
		Status:        model.ConsumerGrantStatusActive,
		ScopesJSON:    "[]",
		TicketVersion: 2,
		GrantedAt:     time.Now().UTC(),
	}).Error)

	grant, err := service.RevokeGrant(RevokeGrantInput{
		Context:     context.Background(),
		BindingID:   binding.ID,
		Consumer:    ConsumerPaiGramBot,
		RevokedAt:   time.Now().UTC(),
		ActorUserID: sql.NullInt64{Int64: int64(binding.OwnerUserID), Valid: true},
	})

	require.ErrorIs(t, err, invalidationErr)
	assert.Nil(t, grant)

	var stored model.ConsumerGrant
	require.NoError(t, db.Where("binding_id = ? AND consumer = ?", binding.ID, ConsumerPaiGramBot).First(&stored).Error)
	assert.Equal(t, model.ConsumerGrantStatusRevoked, stored.Status)
	assert.True(t, stored.RevokedAt.Valid)
	assert.Equal(t, uint64(3), stored.TicketVersion)
	assert.False(t, stored.LastInvalidatedAt.Valid)
}

func TestGrantServiceRevokeGrantRetriesMissingInvalidationForRevokedGrant(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	invalidator := &capturingGrantInvalidator{}
	service := NewGrantService(db, invalidator)
	binding := seedGrantServiceBinding(t, db, "cn:grant-retry-invalid")
	revokedAt := time.Now().UTC().Add(-time.Hour)
	retryAt := time.Now().UTC()
	require.NoError(t, db.Create(&model.ConsumerGrant{
		BindingID:     binding.ID,
		Consumer:      ConsumerPaiGramBot,
		Status:        model.ConsumerGrantStatusRevoked,
		ScopesJSON:    "[]",
		TicketVersion: 5,
		GrantedAt:     time.Now().UTC(),
		RevokedAt:     sql.NullTime{Time: revokedAt, Valid: true},
	}).Error)

	revoked, err := service.RevokeGrant(RevokeGrantInput{
		BindingID: binding.ID,
		Consumer:  ConsumerPaiGramBot,
		RevokedAt: retryAt,
	})

	require.NoError(t, err)
	require.Equal(t, 1, invalidator.calls)
	assert.Equal(t, uint64(5), invalidator.input.MinimumGrantVersion)
	assert.Equal(t, uint64(5), revoked.TicketVersion)
	assert.True(t, revoked.LastInvalidatedAt.Valid)
	assert.True(t, revoked.LastInvalidatedAt.Time.Equal(retryAt))
}

func TestGrantServiceRevokeGrantCallsInvalidatorWithExpectedInput(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	invalidator := &capturingGrantInvalidator{}
	service := NewGrantService(db, invalidator)
	binding := seedGrantServiceBinding(t, db, "cn:grant-invalid-input")
	require.NoError(t, db.Create(&model.ConsumerGrant{
		BindingID:     binding.ID,
		Consumer:      ConsumerPaiGramBot,
		Status:        model.ConsumerGrantStatusActive,
		ScopesJSON:    "[]",
		TicketVersion: 7,
		GrantedAt:     time.Now().UTC(),
	}).Error)
	ctx := context.WithValue(context.Background(), grantInvalidatorContextKey{}, "request-context")

	_, err := service.RevokeGrant(RevokeGrantInput{
		Context:     ctx,
		BindingID:   binding.ID,
		Consumer:    ConsumerPaiGramBot,
		RevokedAt:   time.Now().UTC(),
		ActorUserID: sql.NullInt64{Int64: int64(binding.OwnerUserID), Valid: true},
	})

	require.NoError(t, err)
	require.Equal(t, 1, invalidator.calls)
	assert.Same(t, ctx, invalidator.ctx)
	assert.Equal(t, GrantInvalidationInput{
		BindingID:           binding.ID,
		OwnerUserID:         binding.OwnerUserID,
		Platform:            "mihomo",
		PlatformServiceKey:  "mihomo",
		Consumer:            ConsumerPaiGramBot,
		MinimumGrantVersion: 8,
		ActorType:           "user",
		ActorID:             strconv.FormatUint(binding.OwnerUserID, 10),
	}, invalidator.input)
}

func TestGrantServiceRevokeGrantAuditFailureIsBestEffort(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewGrantService(db)
	binding := seedGrantServiceBinding(t, db, "cn:grant-audit-best-effort")
	require.NoError(t, db.Create(&model.ConsumerGrant{
		BindingID:     binding.ID,
		Consumer:      ConsumerPaiGramBot,
		Status:        model.ConsumerGrantStatusActive,
		ScopesJSON:    "[]",
		TicketVersion: 1,
		GrantedAt:     time.Now().UTC(),
	}).Error)
	require.NoError(t, db.Exec("CREATE TRIGGER audit_events_fail_before_insert BEFORE INSERT ON audit_events FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit disabled'").Error)

	grant, err := service.RevokeGrant(RevokeGrantInput{
		BindingID: binding.ID,
		Consumer:  ConsumerPaiGramBot,
		RevokedAt: time.Now().UTC(),
	})

	require.NoError(t, err)
	require.NotNil(t, grant)
	assert.Equal(t, model.ConsumerGrantStatusRevoked, grant.Status)
	assert.Equal(t, uint64(2), grant.TicketVersion)

	var stored model.ConsumerGrant
	require.NoError(t, db.Where("binding_id = ? AND consumer = ?", binding.ID, ConsumerPaiGramBot).First(&stored).Error)
	assert.Equal(t, model.ConsumerGrantStatusRevoked, stored.Status)
	assert.Equal(t, uint64(2), stored.TicketVersion)
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
	invalidator := &capturingGrantInvalidator{}
	service := NewGrantService(db, invalidator)
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
	require.Equal(t, 1, invalidator.calls)
	assert.Equal(t, "admin", invalidator.input.ActorType)
	assert.Equal(t, strconv.FormatUint(admin.ID, 10), invalidator.input.ActorID)

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

func seedGrantServiceBinding(t *testing.T, db *gorm.DB, externalAccountKey string) model.PlatformAccountBinding {
	t.Helper()
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: ns(externalAccountKey),
		PlatformServiceKey: "mihomo",
		DisplayName:        "Grant Service",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)
	return binding
}

type failingGrantInvalidator struct {
	err error
}

func (f failingGrantInvalidator) InvalidateConsumerGrant(context.Context, GrantInvalidationInput) error {
	return f.err
}

type grantInvalidatorContextKey struct{}

type capturingGrantInvalidator struct {
	calls int
	ctx   context.Context
	input GrantInvalidationInput
}

func (c *capturingGrantInvalidator) InvalidateConsumerGrant(ctx context.Context, input GrantInvalidationInput) error {
	c.calls++
	c.ctx = ctx
	c.input = input
	return nil
}

type serviceGroupPlatformServiceStub struct{}

func (s *serviceGroupPlatformServiceStub) GetEnabledPlatform(string) (*model.PlatformService, error) {
	return &model.PlatformService{ServiceKey: "platform-mihomo-service", ServiceAudience: "platform-mihomo-service"}, nil
}

func (s *serviceGroupPlatformServiceStub) IssueBindingScopedTicket(string, string, *model.PlatformAccountBinding, []string) (string, time.Time, error) {
	return "ticket", time.Now().UTC(), nil
}

func (s *serviceGroupPlatformServiceStub) ConfirmBindingPrimaryProfile(context.Context, string, string, *model.PlatformAccountBinding, string) error {
	return nil
}

func (s *serviceGroupPlatformServiceStub) GetBindingRuntimeSummary(context.Context, string, string, *model.PlatformAccountBinding, []string) (map[string]any, error) {
	return nil, nil
}

func (s *serviceGroupPlatformServiceStub) InvalidateConsumerGrant(context.Context, GrantInvalidationInput) error {
	return nil
}

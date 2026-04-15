package botaccess

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"paigram/internal/model"
	"paigram/internal/testutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupBotAccessServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	return testutil.OpenMySQLTestDB(t, "botaccess_service",
		&model.User{},
		&model.Bot{},
		&model.BotIdentity{},
		&model.PlatformAccountRef{},
		&model.BotAccountGrant{},
	)
}

func TestAccountRefService_ResolveBotUser(t *testing.T) {
	db := setupBotAccessServiceTestDB(t)
	service := &AccountRefService{db: db}

	user := model.User{PrimaryLoginType: model.LoginTypeOAuth, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&user).Error)

	bot := model.Bot{ID: "bot-resolve", Name: "Resolve Bot", Type: "OTHER", Status: "ACTIVE", OwnerUserID: user.ID, APIKey: "resolve-key", APISecret: "resolve-secret", Scopes: "[]", Metadata: "{}"}
	require.NoError(t, db.Create(&bot).Error)

	identity := model.BotIdentity{
		UserID:           user.ID,
		BotID:            bot.ID,
		ExternalUserID:   "external-1",
		ExternalUsername: sql.NullString{String: "alice", Valid: true},
		LinkedAt:         time.Now().UTC(),
	}
	require.NoError(t, db.Create(&identity).Error)

	resolved, err := service.ResolveBotUser(bot.ID, identity.ExternalUserID)
	require.NoError(t, err)
	assert.Equal(t, identity.ID, resolved.ID)
	assert.Equal(t, user.ID, resolved.UserID)
	assert.Equal(t, "alice", resolved.ExternalUsername.String)

	missing, err := service.ResolveBotUser(bot.ID, "missing-user")
	require.ErrorIs(t, err, ErrBotIdentityNotFound)
	assert.Nil(t, missing)
}

func TestAccountRefService_LinkPlatformAccountCreatesGrant(t *testing.T) {
	db := setupBotAccessServiceTestDB(t)
	service := &AccountRefService{db: db}

	identity := seedBotIdentity(t, db, "bot-link", "external-link", 1)

	ref, created, err := service.LinkPlatformAccount(LinkPlatformAccountParams{
		BotID:              identity.BotID,
		ExternalUserID:     identity.ExternalUserID,
		Platform:           "telegram",
		PlatformServiceKey: "tg-main",
		PlatformAccountID:  "acct-1001",
		DisplayName:        "Primary Telegram",
		MetaJSON:           `{"lang":"en"}`,
		GrantScopes:        []string{"messages:read", "messages:write"},
	})
	require.NoError(t, err)
	assert.True(t, created)
	assert.Equal(t, identity.UserID, ref.UserID)
	assert.Equal(t, model.PlatformAccountRefStatusActive, ref.Status)
	assert.Equal(t, "tg-main", ref.PlatformServiceKey)
	assert.True(t, ref.MetaJSON.Valid)
	assert.JSONEq(t, `{"lang":"en"}`, ref.MetaJSON.String)

	var grant model.BotAccountGrant
	require.NoError(t, db.Where("bot_id = ? AND platform_account_ref_id = ?", identity.BotID, ref.ID).First(&grant).Error)
	assert.Equal(t, identity.UserID, grant.UserID)
	assert.Equal(t, ref.ID, grant.PlatformAccountRefID)
	assert.True(t, grant.RevokedAt.Time.IsZero())

	scopes, err := DecodeGrantScopes(grant)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"messages:read", "messages:write"}, scopes)
}

func TestAccountRefService_LinkPlatformAccountRejectsOtherUserOwnership(t *testing.T) {
	db := setupBotAccessServiceTestDB(t)
	service := &AccountRefService{db: db}

	identityA := seedBotIdentity(t, db, "bot-owner-a", "external-owner-a", 21)
	identityB := seedBotIdentity(t, db, "bot-owner-b", "external-owner-b", 22)

	_, _, err := service.LinkPlatformAccount(LinkPlatformAccountParams{
		BotID:              identityA.BotID,
		ExternalUserID:     identityA.ExternalUserID,
		Platform:           "telegram",
		PlatformServiceKey: "tg-main",
		PlatformAccountID:  "acct-shared",
		DisplayName:        "Shared",
		GrantScopes:        []string{"messages:read"},
	})
	require.NoError(t, err)

	_, _, err = service.LinkPlatformAccount(LinkPlatformAccountParams{
		BotID:              identityB.BotID,
		ExternalUserID:     identityB.ExternalUserID,
		Platform:           "telegram",
		PlatformServiceKey: "tg-main",
		PlatformAccountID:  "acct-shared",
		DisplayName:        "Shared",
		GrantScopes:        []string{"messages:read"},
	})
	require.ErrorIs(t, err, ErrPlatformAccountOwnedByOtherUser)
}

func TestAccountRefService_ListAccessibleAccountsFiltersByBotGrant(t *testing.T) {
	db := setupBotAccessServiceTestDB(t)
	service := &AccountRefService{db: db}

	identity := seedBotIdentity(t, db, "bot-list", "external-list", 11)
	seedBotIdentity(t, db, "bot-other", "external-other", 12)

	activeVisible := model.PlatformAccountRef{
		UserID:             identity.UserID,
		Platform:           "telegram",
		PlatformServiceKey: "tg-main",
		PlatformAccountID:  "acct-visible",
		DisplayName:        "Visible",
		Status:             model.PlatformAccountRefStatusActive,
	}
	filteredPlatform := model.PlatformAccountRef{
		UserID:             identity.UserID,
		Platform:           "discord",
		PlatformServiceKey: "dc-main",
		PlatformAccountID:  "acct-discord",
		DisplayName:        "Discord",
		Status:             model.PlatformAccountRefStatusActive,
	}
	inactive := model.PlatformAccountRef{
		UserID:             identity.UserID,
		Platform:           "telegram",
		PlatformServiceKey: "tg-main",
		PlatformAccountID:  "acct-inactive",
		DisplayName:        "Inactive",
		Status:             model.PlatformAccountRefStatusInactive,
	}
	noGrant := model.PlatformAccountRef{
		UserID:             identity.UserID,
		Platform:           "telegram",
		PlatformServiceKey: "tg-main",
		PlatformAccountID:  "acct-no-grant",
		DisplayName:        "No Grant",
		Status:             model.PlatformAccountRefStatusActive,
	}
	revoked := model.PlatformAccountRef{
		UserID:             identity.UserID,
		Platform:           "telegram",
		PlatformServiceKey: "tg-main",
		PlatformAccountID:  "acct-revoked",
		DisplayName:        "Revoked",
		Status:             model.PlatformAccountRefStatusActive,
	}
	require.NoError(t, db.Create(&activeVisible).Error)
	require.NoError(t, db.Create(&filteredPlatform).Error)
	require.NoError(t, db.Create(&inactive).Error)
	require.NoError(t, db.Create(&noGrant).Error)
	require.NoError(t, db.Create(&revoked).Error)

	grantJSON, err := json.Marshal([]string{"scope:a"})
	require.NoError(t, err)

	require.NoError(t, db.Create(&model.BotAccountGrant{UserID: identity.UserID, BotID: identity.BotID, PlatformAccountRefID: activeVisible.ID, Scopes: string(grantJSON), GrantedAt: time.Now().UTC()}).Error)
	require.NoError(t, db.Create(&model.BotAccountGrant{UserID: identity.UserID, BotID: identity.BotID, PlatformAccountRefID: filteredPlatform.ID, Scopes: string(grantJSON), GrantedAt: time.Now().UTC()}).Error)
	require.NoError(t, db.Create(&model.BotAccountGrant{UserID: identity.UserID, BotID: identity.BotID, PlatformAccountRefID: inactive.ID, Scopes: string(grantJSON), GrantedAt: time.Now().UTC()}).Error)
	require.NoError(t, db.Create(&model.BotAccountGrant{UserID: identity.UserID, BotID: identity.BotID, PlatformAccountRefID: revoked.ID, Scopes: string(grantJSON), GrantedAt: time.Now().UTC(), RevokedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}}).Error)
	require.NoError(t, db.Create(&model.BotAccountGrant{UserID: identity.UserID, BotID: "bot-other", PlatformAccountRefID: noGrant.ID, Scopes: string(grantJSON), GrantedAt: time.Now().UTC()}).Error)

	accounts, err := service.ListAccessibleAccounts(identity.BotID, identity.ExternalUserID, "telegram")
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	assert.Equal(t, activeVisible.ID, accounts[0].ID)
	assert.Equal(t, "acct-visible", accounts[0].PlatformAccountID)
}

func TestAccountRefService_GetGrantedAccount(t *testing.T) {
	db := setupBotAccessServiceTestDB(t)
	service := &AccountRefService{db: db}

	identity := seedBotIdentity(t, db, "bot-grant", "external-grant", 31)
	ref := model.PlatformAccountRef{
		UserID:             identity.UserID,
		Platform:           "telegram",
		PlatformServiceKey: "tg-main",
		PlatformAccountID:  "acct-lookup",
		DisplayName:        "Lookup",
		Status:             model.PlatformAccountRefStatusActive,
	}
	require.NoError(t, db.Create(&ref).Error)
	grantJSON, err := json.Marshal([]string{"scope:a", "scope:b"})
	require.NoError(t, err)
	require.NoError(t, db.Create(&model.BotAccountGrant{UserID: identity.UserID, BotID: identity.BotID, PlatformAccountRefID: ref.ID, Scopes: string(grantJSON), GrantedAt: time.Now().UTC()}).Error)

	resolvedIdentity, resolvedRef, resolvedGrant, err := service.GetGrantedAccount(identity.BotID, identity.ExternalUserID, ref.ID)
	require.NoError(t, err)
	assert.Equal(t, identity.ID, resolvedIdentity.ID)
	assert.Equal(t, ref.ID, resolvedRef.ID)
	assert.Equal(t, ref.ID, resolvedGrant.PlatformAccountRefID)
}

func seedBotIdentity(t *testing.T, db *gorm.DB, botID, externalUserID string, suffix uint64) model.BotIdentity {
	t.Helper()

	user := model.User{PrimaryLoginType: model.LoginTypeOAuth, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&user).Error)

	bot := model.Bot{
		ID:          botID,
		Name:        "Bot " + botID,
		Type:        "OTHER",
		Status:      "ACTIVE",
		OwnerUserID: user.ID,
		APIKey:      botID + "-key",
		APISecret:   botID + "-secret",
		Scopes:      "[]",
		Metadata:    "{}",
	}
	require.NoError(t, db.Create(&bot).Error)

	identity := model.BotIdentity{
		UserID:           user.ID,
		BotID:            bot.ID,
		ExternalUserID:   externalUserID,
		ExternalUsername: sql.NullString{String: "user", Valid: true},
		LinkedAt:         time.Now().UTC().Add(time.Duration(suffix) * time.Second),
	}
	require.NoError(t, db.Create(&identity).Error)

	return identity
}

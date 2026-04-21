package botaccess

import (
	"database/sql"
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
		&model.PlatformAccountBinding{},
		&model.PlatformAccountProfile{},
		&model.ConsumerGrant{},
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

func TestAccountRefService_ListAccessibleAccountsFiltersByConsumerGrant(t *testing.T) {
	db := setupBotAccessServiceTestDB(t)
	service := &AccountRefService{db: db}

	identity := seedBotIdentity(t, db, "bot-paigram", "external-list", 11)
	otherIdentity := seedBotIdentity(t, db, "bot-other", "external-other", 12)
	otherBot := model.Bot{ID: "bot-other-same-user", Name: "Other Same User", Type: "OTHER", Status: "ACTIVE", OwnerUserID: identity.UserID, APIKey: "other-same-user-key", APISecret: "other-same-user-secret", Scopes: "[]", Metadata: "{}"}
	require.NoError(t, db.Create(&otherBot).Error)
	require.NoError(t, db.Create(&model.BotIdentity{UserID: identity.UserID, BotID: otherBot.ID, ExternalUserID: "external-list-other-bot", LinkedAt: time.Now().UTC()}).Error)

	activeVisible := model.PlatformAccountBinding{
		OwnerUserID:        identity.UserID,
		Platform:           "telegram",
		ExternalAccountKey: sql.NullString{String: "acct-visible", Valid: true},
		PlatformServiceKey: "tg-main",
		DisplayName:        "Visible",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	filteredPlatform := model.PlatformAccountBinding{
		OwnerUserID:        identity.UserID,
		Platform:           "discord",
		ExternalAccountKey: sql.NullString{String: "acct-discord", Valid: true},
		PlatformServiceKey: "dc-main",
		DisplayName:        "Discord",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	inactive := model.PlatformAccountBinding{
		OwnerUserID:        identity.UserID,
		Platform:           "telegram",
		ExternalAccountKey: sql.NullString{String: "acct-inactive", Valid: true},
		PlatformServiceKey: "tg-main",
		DisplayName:        "Inactive",
		Status:             model.PlatformAccountBindingStatusDisabled,
	}
	noGrant := model.PlatformAccountBinding{
		OwnerUserID:        identity.UserID,
		Platform:           "telegram",
		ExternalAccountKey: sql.NullString{String: "acct-no-grant", Valid: true},
		PlatformServiceKey: "tg-main",
		DisplayName:        "No Grant",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	revoked := model.PlatformAccountBinding{
		OwnerUserID:        identity.UserID,
		Platform:           "telegram",
		ExternalAccountKey: sql.NullString{String: "acct-revoked", Valid: true},
		PlatformServiceKey: "tg-main",
		DisplayName:        "Revoked",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	otherOwner := model.PlatformAccountBinding{
		OwnerUserID:        otherIdentity.UserID,
		Platform:           "telegram",
		ExternalAccountKey: sql.NullString{String: "acct-other-owner", Valid: true},
		PlatformServiceKey: "tg-main",
		DisplayName:        "Other Owner",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&activeVisible).Error)
	require.NoError(t, db.Create(&filteredPlatform).Error)
	require.NoError(t, db.Create(&inactive).Error)
	require.NoError(t, db.Create(&noGrant).Error)
	require.NoError(t, db.Create(&revoked).Error)
	require.NoError(t, db.Create(&otherOwner).Error)

	require.NoError(t, db.Create(&model.ConsumerGrant{BindingID: activeVisible.ID, Consumer: consumerName(identity.BotID), Status: model.ConsumerGrantStatusActive, GrantedAt: time.Now().UTC()}).Error)
	require.NoError(t, db.Create(&model.ConsumerGrant{BindingID: filteredPlatform.ID, Consumer: consumerName(identity.BotID), Status: model.ConsumerGrantStatusActive, GrantedAt: time.Now().UTC()}).Error)
	require.NoError(t, db.Create(&model.ConsumerGrant{BindingID: inactive.ID, Consumer: consumerName(identity.BotID), Status: model.ConsumerGrantStatusActive, GrantedAt: time.Now().UTC()}).Error)
	require.NoError(t, db.Create(&model.ConsumerGrant{BindingID: revoked.ID, Consumer: consumerName(identity.BotID), Status: model.ConsumerGrantStatusRevoked, GrantedAt: time.Now().UTC(), RevokedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}}).Error)
	require.NoError(t, db.Create(&model.ConsumerGrant{BindingID: otherOwner.ID, Consumer: consumerName(identity.BotID), Status: model.ConsumerGrantStatusActive, GrantedAt: time.Now().UTC()}).Error)

	accounts, err := service.ListAccessibleAccounts(identity.BotID, identity.ExternalUserID, "telegram")
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	assert.Equal(t, activeVisible.ID, accounts[0].ID)
	assert.Equal(t, activeVisible.OwnerUserID, accounts[0].UserID)
	assert.Equal(t, "acct-visible", accounts[0].PlatformAccountID)

	otherBotAccounts, err := service.ListAccessibleAccounts(otherBot.ID, "external-list-other-bot", "telegram")
	require.NoError(t, err)
	assert.Empty(t, otherBotAccounts)
}

func TestAccountRefService_GetGrantedBinding(t *testing.T) {
	db := setupBotAccessServiceTestDB(t)
	service := &AccountRefService{db: db}

	identity := seedBotIdentity(t, db, "bot-paigram", "external-grant", 31)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        identity.UserID,
		Platform:           "telegram",
		ExternalAccountKey: sql.NullString{String: "acct-lookup", Valid: true},
		PlatformServiceKey: "tg-main",
		DisplayName:        "Lookup",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)
	grant := model.ConsumerGrant{BindingID: binding.ID, Consumer: consumerName(identity.BotID), Status: model.ConsumerGrantStatusActive, GrantedAt: time.Now().UTC()}
	require.NoError(t, db.Create(&grant).Error)

	resolvedIdentity, resolvedBinding, resolvedGrant, err := service.GetGrantedBinding(identity.BotID, identity.ExternalUserID, binding.ID, 0)
	require.NoError(t, err)
	assert.Equal(t, identity.ID, resolvedIdentity.ID)
	assert.Equal(t, binding.ID, resolvedBinding.ID)
	assert.Equal(t, binding.ID, resolvedGrant.BindingID)
}

func TestAccountRefService_GetGrantedBindingRejectsProfileFromOtherBinding(t *testing.T) {
	db := setupBotAccessServiceTestDB(t)
	service := &AccountRefService{db: db}

	identity := seedBotIdentity(t, db, "bot-paigram", "external-grant-profile", 32)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        identity.UserID,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:binding", Valid: true},
		PlatformServiceKey: "platform-mihomo-service",
		DisplayName:        "Binding",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	otherBinding := model.PlatformAccountBinding{
		OwnerUserID:        identity.UserID,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:other-binding", Valid: true},
		PlatformServiceKey: "platform-mihomo-service",
		DisplayName:        "Other Binding",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)
	require.NoError(t, db.Create(&otherBinding).Error)
	require.NoError(t, db.Create(&model.ConsumerGrant{BindingID: binding.ID, Consumer: consumerName(identity.BotID), Status: model.ConsumerGrantStatusActive, GrantedAt: time.Now().UTC()}).Error)
	foreignProfile := model.PlatformAccountProfile{
		BindingID:          otherBinding.ID,
		PlatformProfileKey: "mihomo:20002",
		GameBiz:            "hk4e_cn",
		Region:             "cn_gf01",
		PlayerUID:          "20002",
		Nickname:           "Foreign",
	}
	require.NoError(t, db.Create(&foreignProfile).Error)

	resolvedIdentity, resolvedBinding, resolvedGrant, err := service.GetGrantedBinding(identity.BotID, identity.ExternalUserID, binding.ID, foreignProfile.ID)
	require.ErrorIs(t, err, ErrPlatformAccountMissing)
	assert.Nil(t, resolvedIdentity)
	assert.Nil(t, resolvedBinding)
	assert.Nil(t, resolvedGrant)
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

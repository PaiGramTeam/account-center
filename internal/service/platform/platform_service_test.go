package platform

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"paigram/internal/config"
	"paigram/internal/model"
	"paigram/internal/testutil"
)

type fakeSummaryProxy struct {
	endpoint          string
	ticket            string
	platformAccountID string
	summary           map[string]any
	err               error
}

func (f *fakeSummaryProxy) GetCredentialSummary(_ context.Context, endpoint, ticket, platformAccountID string) (map[string]any, error) {
	f.endpoint = endpoint
	f.ticket = ticket
	f.platformAccountID = platformAccountID
	if f.err != nil {
		return nil, f.err
	}
	return f.summary, nil
}

func TestPlatformServiceGetEnabledPlatform(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "platform_registry", &model.PlatformService{})
	require.NoError(t, db.Create(&model.PlatformService{
		PlatformKey:          "mihomo",
		DisplayName:          "Mihomo",
		ServiceKey:           "platform-mihomo-service",
		ServiceAudience:      "platform-mihomo-service",
		DiscoveryType:        "static",
		Endpoint:             "127.0.0.1:9000",
		Enabled:              true,
		SupportedActionsJSON: `["bind_credential","delete_credential"]`,
		CredentialSchemaJSON: `{}`,
	}).Error)

	svc := NewServiceGroup(db)
	platform, err := svc.PlatformService.GetEnabledPlatform("mihomo")
	require.NoError(t, err)
	require.Equal(t, "platform-mihomo-service", platform.ServiceKey)
}

func TestPlatformServiceListEnabledPlatforms(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "platform_registry_list", &model.PlatformService{})
	require.NoError(t, db.Create(&model.PlatformService{
		PlatformKey:          "zenless",
		DisplayName:          "Zenless Zone Zero",
		ServiceKey:           "platform-zenless-service",
		ServiceAudience:      "platform-zenless-service",
		DiscoveryType:        "static",
		Endpoint:             "127.0.0.1:9001",
		Enabled:              true,
		SupportedActionsJSON: `["bind_credential"]`,
		CredentialSchemaJSON: `{}`,
	}).Error)
	require.NoError(t, db.Create(&model.PlatformService{
		PlatformKey:          "mihomo",
		DisplayName:          "Mihomo",
		ServiceKey:           "platform-mihomo-service",
		ServiceAudience:      "platform-mihomo-service",
		DiscoveryType:        "static",
		Endpoint:             "127.0.0.1:9000",
		Enabled:              true,
		SupportedActionsJSON: `["bind_credential","delete_credential"]`,
		CredentialSchemaJSON: `{}`,
	}).Error)
	disabled := &model.PlatformService{
		PlatformKey:          "disabled",
		DisplayName:          "Disabled",
		ServiceKey:           "platform-disabled-service",
		ServiceAudience:      "platform-disabled-service",
		DiscoveryType:        "static",
		Endpoint:             "127.0.0.1:9002",
		Enabled:              false,
		SupportedActionsJSON: `[]`,
		CredentialSchemaJSON: `{}`,
	}
	require.NoError(t, db.Create(disabled).Error)
	require.NoError(t, db.Model(disabled).Update("enabled", false).Error)

	svc := NewServiceGroup(db)
	platforms, err := svc.PlatformService.ListEnabledPlatforms()
	require.NoError(t, err)
	require.Len(t, platforms, 2)
	require.Equal(t, []string{"mihomo", "zenless"}, []string{platforms[0].PlatformKey, platforms[1].PlatformKey})
}

func TestPlatformServiceBuildsWebActorTicketClaims(t *testing.T) {
	claims := buildPlatformServiceTicketClaims("web_user", "session-123", 7, 11, "mihomo", "hoyo_ref_11_10001", []string{"mihomo.credential.read_meta"})
	require.Equal(t, "web_user", claims.ActorType)
	require.Equal(t, "session-123", claims.ActorID)
	require.Equal(t, uint64(7), claims.OwnerUserID)
	require.Equal(t, uint64(11), claims.PlatformAccountRefID)
	require.Equal(t, "mihomo", claims.Platform)
	require.Equal(t, "hoyo_ref_11_10001", claims.PlatformAccountID)
	require.Equal(t, []string{"mihomo.credential.read_meta"}, claims.Scopes)
}

func TestPlatformServiceIssueActorScopedTicket(t *testing.T) {
	svc := PlatformService{}
	require.NoError(t, svc.ConfigureAuth(config.AuthConfig{
		ServiceTicketTTLSeconds: 300,
		ServiceTicketIssuer:     "account-center",
		ServiceTicketSigningKey: "0123456789abcdef0123456789abcdef",
	}))

	ref := &model.PlatformAccountRef{
		ID:                11,
		UserID:            7,
		Platform:          "mihomo",
		PlatformAccountID: "hoyo_ref_11_10001",
		Status:            model.PlatformAccountRefStatusActive,
	}

	tokenString, expiresAt, err := svc.IssueActorScopedTicket("web_user", "session-123", ref.UserID, ref, []string{"mihomo.credential.read_meta"}, "platform-mihomo-service")
	require.NoError(t, err)
	require.WithinDuration(t, time.Now().UTC().Add(5*time.Minute), expiresAt, 3*time.Second)

	parsed := &ServiceTicketClaims{}
	token, err := jwt.ParseWithClaims(tokenString, parsed, func(token *jwt.Token) (any, error) {
		return []byte("0123456789abcdef0123456789abcdef"), nil
	})
	require.NoError(t, err)
	require.True(t, token.Valid)
	require.Equal(t, "web_user", parsed.ActorType)
	require.Equal(t, "session-123", parsed.ActorID)
	require.Equal(t, ref.UserID, parsed.OwnerUserID)
	require.Equal(t, ref.Platform, parsed.Platform)
	require.Equal(t, ref.ID, parsed.PlatformAccountRefID)
	require.Equal(t, ref.PlatformAccountID, parsed.PlatformAccountID)
	require.Equal(t, []string{"mihomo.credential.read_meta"}, parsed.Scopes)
	require.Equal(t, "account-center", parsed.Issuer)
	require.Equal(t, "user:7", parsed.Subject)
	require.Equal(t, []string{"platform-mihomo-service"}, []string(parsed.Audience))
	require.WithinDuration(t, expiresAt, parsed.ExpiresAt.Time, time.Second)
	require.NotEmpty(t, parsed.ID)
}

func TestPlatformServiceConfigureAuthAllowsEmptySigningKeyForReadOnlyRoutes(t *testing.T) {
	svc := PlatformService{}
	require.NoError(t, svc.ConfigureAuth(config.AuthConfig{
		ServiceTicketTTLSeconds: 300,
		ServiceTicketIssuer:     "account-center",
		ServiceTicketSigningKey: "",
	}))
	require.Equal(t, 5*time.Minute, svc.ttl)
	require.Equal(t, "account-center", svc.issuer)
	require.Empty(t, svc.signingKey)
}

func TestPlatformServiceListPlatformViews(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "platform_registry_views", &model.PlatformService{})
	require.NoError(t, db.Create(&model.PlatformService{
		PlatformKey:          "mihomo",
		DisplayName:          "Mihomo",
		ServiceKey:           "platform-mihomo-service",
		ServiceAudience:      "platform-mihomo-service",
		DiscoveryType:        "static",
		Endpoint:             "127.0.0.1:9000",
		Enabled:              true,
		SupportedActionsJSON: `["bind_credential","delete_credential"]`,
		CredentialSchemaJSON: `{"type":"object"}`,
	}).Error)

	svc := NewServiceGroup(db)
	views, err := svc.PlatformService.ListEnabledPlatformViews()
	require.NoError(t, err)
	require.Len(t, views, 1)
	require.Equal(t, PlatformListView{
		Platform:         "mihomo",
		DisplayName:      "Mihomo",
		SupportedActions: []string{"bind_credential", "delete_credential"},
	}, views[0])
}

func TestPlatformServiceGetPlatformSchemaView(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "platform_registry_schema_view", &model.PlatformService{})
	require.NoError(t, db.Create(&model.PlatformService{
		PlatformKey:          "mihomo",
		DisplayName:          "Mihomo",
		ServiceKey:           "platform-mihomo-service",
		ServiceAudience:      "platform-mihomo-service",
		DiscoveryType:        "static",
		Endpoint:             "127.0.0.1:9000",
		Enabled:              true,
		SupportedActionsJSON: `["bind_credential"]`,
		CredentialSchemaJSON: `{"type":"object","required":["cookie_bundle"]}`,
	}).Error)

	svc := NewServiceGroup(db)
	view, err := svc.PlatformService.GetPlatformSchemaView("mihomo")
	require.NoError(t, err)
	require.Equal(t, &PlatformSchemaView{
		Platform:         "mihomo",
		DisplayName:      "Mihomo",
		SupportedActions: []string{"bind_credential"},
		CredentialSchema: map[string]any{"type": "object", "required": []any{"cookie_bundle"}},
	}, view)
}

func TestPlatformServiceGetPlatformAccountSummaryIssuesScopedTicketAndCallsProxy(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "platform_registry_summary_proxy", &model.PlatformService{}, &model.User{}, &model.PlatformAccountRef{})
	require.NoError(t, db.Create(&model.PlatformService{
		PlatformKey:          "mihomo",
		DisplayName:          "Mihomo",
		ServiceKey:           "platform-mihomo-service",
		ServiceAudience:      "platform-mihomo-service",
		DiscoveryType:        "static",
		Endpoint:             "127.0.0.1:9000",
		Enabled:              true,
		SupportedActionsJSON: `[]`,
		CredentialSchemaJSON: `{}`,
	}).Error)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	ref := model.PlatformAccountRef{
		UserID:             owner.ID,
		Platform:           "mihomo",
		PlatformServiceKey: "platform-mihomo-service",
		PlatformAccountID:  "hoyo_ref_11_10001",
		DisplayName:        "Traveler",
		Status:             model.PlatformAccountRefStatusActive,
	}
	require.NoError(t, db.Create(&ref).Error)

	svc := NewServiceGroup(db).PlatformService
	require.NoError(t, svc.ConfigureAuth(config.AuthConfig{
		ServiceTicketTTLSeconds: 300,
		ServiceTicketIssuer:     "account-center",
		ServiceTicketSigningKey: "0123456789abcdef0123456789abcdef",
	}))
	proxy := &fakeSummaryProxy{summary: map[string]any{"status": "active"}}
	svc.SetSummaryProxy(proxy)

	summary, err := svc.GetPlatformAccountSummary(context.Background(), "web_user", "session:99", owner.ID, ref.ID, []string{"mihomo.credential.read_meta"})
	require.NoError(t, err)
	require.Equal(t, map[string]any{"status": "active"}, summary)
	require.Equal(t, "127.0.0.1:9000", proxy.endpoint)
	require.Equal(t, ref.PlatformAccountID, proxy.platformAccountID)

	parsed := &ServiceTicketClaims{}
	token, err := jwt.ParseWithClaims(proxy.ticket, parsed, func(token *jwt.Token) (any, error) {
		return []byte("0123456789abcdef0123456789abcdef"), nil
	})
	require.NoError(t, err)
	require.True(t, token.Valid)
	require.Equal(t, "web_user", parsed.ActorType)
	require.Equal(t, "session:99", parsed.ActorID)
	require.Equal(t, owner.ID, parsed.OwnerUserID)
	require.Equal(t, ref.ID, parsed.PlatformAccountRefID)
	require.Equal(t, ref.PlatformAccountID, parsed.PlatformAccountID)
	require.Equal(t, []string{"mihomo.credential.read_meta"}, parsed.Scopes)
	require.Equal(t, []string{"platform-mihomo-service"}, []string(parsed.Audience))
}

func TestPlatformServiceGetPlatformAccountSummaryReturnsServiceUnavailableWhenRegistryMissing(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "platform_registry_missing_summary", &model.PlatformService{}, &model.User{}, &model.PlatformAccountRef{})
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	ref := model.PlatformAccountRef{
		UserID:             owner.ID,
		Platform:           "mihomo",
		PlatformServiceKey: "platform-mihomo-service",
		PlatformAccountID:  "hoyo_ref_11_10001",
		DisplayName:        "Traveler",
		Status:             model.PlatformAccountRefStatusActive,
	}
	require.NoError(t, db.Create(&ref).Error)

	svc := NewServiceGroup(db).PlatformService
	require.NoError(t, svc.ConfigureAuth(config.AuthConfig{
		ServiceTicketTTLSeconds: 300,
		ServiceTicketIssuer:     "account-center",
		ServiceTicketSigningKey: "0123456789abcdef0123456789abcdef",
	}))
	svc.SetSummaryProxy(&fakeSummaryProxy{summary: map[string]any{"status": "active"}})

	_, err := svc.GetPlatformAccountSummary(context.Background(), "web_user", "session:99", owner.ID, ref.ID, []string{"mihomo.credential.read_meta"})
	require.ErrorIs(t, err, ErrPlatformServiceUnavailable)
}

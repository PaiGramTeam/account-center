package platform

import (
	"context"
	"database/sql"
	"net"
	"testing"
	"time"

	platformv1 "github.com/PaiGramTeam/proto-contracts/platform/v1"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"paigram/internal/config"
	"paigram/internal/model"
	"paigram/internal/service/platformbinding"
	"paigram/internal/testutil"
)

type fakeSummaryProxy struct {
	endpoint          string
	ticket            string
	platformAccountID string
	summary           map[string]any
	err               error
	calls             int
}

func (f *fakeSummaryProxy) GetCredentialSummary(_ context.Context, endpoint, ticket, platformAccountID string) (map[string]any, error) {
	f.calls++
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

func TestPlatformServiceBuildsBindingActorTicketClaims(t *testing.T) {
	claims := buildBindingScopedTicketClaims("user", "session-123", 7, 11, "mihomo", "platform-mihomo-service", "hoyo_ref_11_10001", []string{"mihomo.credential.read_meta"})
	require.Equal(t, "user", claims.ActorType)
	require.Equal(t, "session-123", claims.ActorID)
	require.Equal(t, uint64(7), claims.OwnerUserID)
	require.Equal(t, uint64(11), claims.BindingID)
	require.Equal(t, "mihomo", claims.Platform)
	require.Equal(t, "platform-mihomo-service", claims.PlatformServiceKey)
	require.Equal(t, "hoyo_ref_11_10001", claims.PlatformAccountID)
	require.Equal(t, []string{"mihomo.credential.read_meta"}, claims.Scopes)
}

func TestIssueLegacyRefScopedTicketSupportsUserAdminAndConsumer(t *testing.T) {
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

	for _, tc := range []struct {
		name    string
		actor   string
		actorID string
		scopes  []string
	}{
		{name: "user", actor: "user", actorID: "session:1", scopes: []string{"binding:write"}},
		{name: "admin", actor: "admin", actorID: "user:1", scopes: []string{"binding:delete"}},
		{name: "consumer", actor: "consumer", actorID: "paigram-bot", scopes: []string{"profile:read"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokenString, expiresAt, err := svc.IssueLegacyRefScopedTicket(tc.actor, tc.actorID, ref.UserID, ref, tc.scopes, "platform-mihomo-service")
			require.NoError(t, err)
			require.WithinDuration(t, time.Now().UTC().Add(5*time.Minute), expiresAt, 3*time.Second)

			parsed := &ServiceTicketClaims{}
			token, err := jwt.ParseWithClaims(tokenString, parsed, func(token *jwt.Token) (any, error) {
				return []byte("0123456789abcdef0123456789abcdef"), nil
			})
			require.NoError(t, err)
			require.True(t, token.Valid)
			require.Equal(t, tc.actor, parsed.ActorType)
			require.Equal(t, tc.actorID, parsed.ActorID)
			require.Equal(t, ref.UserID, parsed.OwnerUserID)
			require.Equal(t, ref.Platform, parsed.Platform)
			require.Equal(t, ref.ID, parsed.BindingID)
			require.Equal(t, ref.PlatformAccountID, parsed.PlatformAccountID)
			require.Equal(t, tc.scopes, parsed.Scopes)
			require.Equal(t, "account-center", parsed.Issuer)
			require.Equal(t, "user:7", parsed.Subject)
			require.Equal(t, []string{"platform-mihomo-service"}, []string(parsed.Audience))
			require.WithinDuration(t, expiresAt, parsed.ExpiresAt.Time, time.Second)
			require.NotEmpty(t, parsed.ID)
		})
	}
}

func TestIssueLegacyRefScopedTicketRejectsLegacyWebUserActor(t *testing.T) {
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

	_, _, err := svc.IssueLegacyRefScopedTicket("web_user", "session:1", ref.UserID, ref, []string{"binding:write"}, "platform-mihomo-service")
	require.ErrorIs(t, err, ErrInvalidTicketConfig)
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

func TestPlatformServiceInvalidateConsumerGrantCallsPlatformService(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "platform_registry_grant_invalidation", &model.PlatformService{})
	require.NoError(t, db.Create(&model.PlatformService{
		PlatformKey:          "mihomo",
		DisplayName:          "Mihomo",
		ServiceKey:           "platform-mihomo-service",
		ServiceAudience:      "platform-mihomo-service",
		DiscoveryType:        "static",
		Endpoint:             "bufnet",
		Enabled:              true,
		SupportedActionsJSON: `[]`,
		CredentialSchemaJSON: `{}`,
	}).Error)

	stub := &grantInvalidationPlatformServiceStub{response: &platformv1.InvalidateConsumerGrantResponse{Success: true}}
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	platformv1.RegisterPlatformServiceServer(server, stub)
	go server.Serve(listener)
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	svc := NewServiceGroup(db).PlatformService
	require.NoError(t, svc.ConfigureAuth(config.AuthConfig{
		ServiceTicketTTLSeconds: 300,
		ServiceTicketIssuer:     "account-center",
		ServiceTicketSigningKey: "0123456789abcdef0123456789abcdef",
	}))
	svc.dial = func(ctx context.Context, endpoint string) (*grpc.ClientConn, error) {
		require.Equal(t, "bufnet", endpoint)
		return grpc.DialContext(ctx, "passthrough:///bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
	}

	err := svc.InvalidateConsumerGrant(context.Background(), platformbinding.GrantInvalidationInput{
		BindingID:           42,
		OwnerUserID:         7,
		Platform:            "mihomo",
		PlatformServiceKey:  "platform-mihomo-service",
		Consumer:            platformbinding.ConsumerPaiGramBot,
		MinimumGrantVersion: 8,
		ActorType:           "admin",
		ActorID:             "admin:7",
	})
	require.NoError(t, err)
	require.NotNil(t, stub.lastRequest)
	require.Equal(t, uint64(42), stub.lastRequest.GetBindingId())
	require.Equal(t, platformbinding.ConsumerPaiGramBot, stub.lastRequest.GetConsumer())
	require.Equal(t, uint64(8), stub.lastRequest.GetMinimumGrantVersion())

	parsed := &ServiceTicketClaims{}
	token, err := jwt.ParseWithClaims(stub.lastRequest.GetServiceTicket(), parsed, func(token *jwt.Token) (any, error) {
		return []byte("0123456789abcdef0123456789abcdef"), nil
	})
	require.NoError(t, err)
	require.True(t, token.Valid)
	require.Equal(t, "admin", parsed.ActorType)
	require.Equal(t, "admin:7", parsed.ActorID)
	require.Equal(t, uint64(7), parsed.OwnerUserID)
	require.Equal(t, uint64(42), parsed.BindingID)
	require.Equal(t, "mihomo", parsed.Platform)
	require.Equal(t, "platform-mihomo-service", parsed.PlatformServiceKey)
	require.Equal(t, []string{"mihomo.consumer_grant.invalidate"}, parsed.Scopes)
	require.Equal(t, []string{"platform-mihomo-service"}, []string(parsed.Audience))
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

type grantInvalidationPlatformServiceStub struct {
	platformv1.UnimplementedPlatformServiceServer
	response    *platformv1.InvalidateConsumerGrantResponse
	lastRequest *platformv1.InvalidateConsumerGrantRequest
}

func (s *grantInvalidationPlatformServiceStub) InvalidateConsumerGrant(_ context.Context, req *platformv1.InvalidateConsumerGrantRequest) (*platformv1.InvalidateConsumerGrantResponse, error) {
	s.lastRequest = req
	return s.response, nil
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
	db := testutil.OpenMySQLTestDB(
		t,
		"platform_registry_summary_proxy",
		&model.PlatformService{},
		&model.User{},
		&model.PlatformAccountRef{},
		&model.PlatformAccountBinding{},
		&model.PlatformAccountProfile{},
	)
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

	summary, err := svc.GetPlatformAccountSummary(context.Background(), "user", "session:99", owner.ID, ref.ID, []string{"mihomo.credential.read_meta"})
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
	require.Equal(t, "user", parsed.ActorType)
	require.Equal(t, "session:99", parsed.ActorID)
	require.Equal(t, owner.ID, parsed.OwnerUserID)
	require.Equal(t, ref.ID, parsed.BindingID)
	require.Equal(t, ref.PlatformAccountID, parsed.PlatformAccountID)
	require.Equal(t, []string{"mihomo.credential.read_meta"}, parsed.Scopes)
	require.Equal(t, []string{"platform-mihomo-service"}, []string(parsed.Audience))
}

func TestPlatformServiceGetPlatformAccountSummaryReturnsBindingProjectionWithoutLegacyRef(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "platform_registry_binding_summary", &model.User{}, &model.PlatformAccountBinding{}, &model.PlatformAccountProfile{})
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: sql.NullString{String: "cn:summary-binding", Valid: true},
		PlatformServiceKey: "platform-mihomo-service",
		DisplayName:        "Traveler",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)
	profiles := []model.PlatformAccountProfile{
		{BindingID: binding.ID, PlatformProfileKey: "mihomo:10001", GameBiz: "hk4e_cn", Region: "cn_gf01", PlayerUID: "10001", Nickname: "Traveler", IsPrimary: true},
		{BindingID: binding.ID, PlatformProfileKey: "mihomo:10002", GameBiz: "hk4e_global", Region: "os_asia", PlayerUID: "10002", Nickname: "Lumine"},
	}
	require.NoError(t, db.Create(&profiles).Error)
	require.NoError(t, db.Model(&binding).Update("primary_profile_id", profiles[0].ID).Error)

	svc := NewServiceGroup(db).PlatformService
	summary, err := svc.GetPlatformAccountSummary(context.Background(), "user", "session:99", owner.ID, binding.ID, []string{"mihomo.credential.read_meta"})
	require.NoError(t, err)
	require.Equal(t, binding.ID, summary["binding_id"])
	require.Equal(t, binding.DisplayName, summary["display_name"])
	require.Equal(t, int64(profiles[0].ID), summary["primary_profile_id"])
	items, ok := summary["profiles"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, items, 2)
	require.Equal(t, profiles[0].PlayerUID, items[0]["player_uid"])
}

func TestPlatformServiceGetPlatformAccountSummaryReturnsServiceUnavailableWhenRegistryMissing(t *testing.T) {
	db := testutil.OpenMySQLTestDB(
		t,
		"platform_registry_missing_summary",
		&model.PlatformService{},
		&model.User{},
		&model.PlatformAccountRef{},
		&model.PlatformAccountBinding{},
		&model.PlatformAccountProfile{},
	)
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

	_, err := svc.GetPlatformAccountSummary(context.Background(), "user", "session:99", owner.ID, ref.ID, []string{"mihomo.credential.read_meta"})
	require.ErrorIs(t, err, ErrPlatformServiceUnavailable)
}

func TestPlatformServiceGetPlatformAccountSummaryPrefersGenericProxy(t *testing.T) {
	db := testutil.OpenMySQLTestDB(
		t,
		"platform_registry_generic_summary_proxy",
		&model.PlatformService{},
		&model.User{},
		&model.PlatformAccountRef{},
		&model.PlatformAccountBinding{},
		&model.PlatformAccountProfile{},
	)
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
	legacyProxy := &fakeSummaryProxy{summary: map[string]any{"path": "legacy"}}
	genericProxy := &fakeSummaryProxy{summary: map[string]any{"path": "generic"}}
	svc.SetSummaryProxy(legacyProxy)
	svc.SetGenericSummaryProxy(genericProxy)

	summary, err := svc.GetPlatformAccountSummary(context.Background(), "user", "session:99", owner.ID, ref.ID, []string{"mihomo.credential.read_meta"})
	require.NoError(t, err)
	require.Equal(t, map[string]any{"path": "generic"}, summary)
	require.Equal(t, 0, legacyProxy.calls)
	require.Equal(t, 1, genericProxy.calls)
	require.Equal(t, "127.0.0.1:9000", genericProxy.endpoint)
	require.Equal(t, ref.PlatformAccountID, genericProxy.platformAccountID)
}

func TestPlatformServiceGetPlatformAccountSummaryReturnsGenericProxyError(t *testing.T) {
	db := testutil.OpenMySQLTestDB(
		t,
		"platform_registry_generic_summary_error",
		&model.PlatformService{},
		&model.User{},
		&model.PlatformAccountRef{},
		&model.PlatformAccountBinding{},
		&model.PlatformAccountProfile{},
	)
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
	genericProxy := &fakeSummaryProxy{err: grpcstatus.Error(codes.Unavailable, "downstream unavailable")}
	svc.SetGenericSummaryProxy(genericProxy)

	_, err := svc.GetPlatformAccountSummary(context.Background(), "user", "session:99", owner.ID, ref.ID, []string{"mihomo.credential.read_meta"})
	require.Error(t, err)
	require.Equal(t, 1, genericProxy.calls)
}

package service_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/grpc/interceptor"
	pb "paigram/internal/grpc/pb/v1"
	grpcservice "paigram/internal/grpc/service"
	"paigram/internal/model"
	"paigram/internal/service/botaccess"
	"paigram/internal/testutil"
)

const botAccessServiceTestSigningKey = "0123456789abcdef0123456789abcdef"

func TestBotAccessServiceAuthenticatedFlow(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "bot_access_grpc",
		&model.User{},
		&model.UserEmail{},
		&model.Bot{},
		&model.BotToken{},
		&model.BotIdentity{},
		&model.PlatformAccountRef{},
		&model.BotAccountGrant{},
		&model.PlatformAccountBinding{},
		&model.PlatformAccountProfile{},
		&model.ConsumerGrant{},
	)

	bot, identityUser, ref := seedBotAccessGRPCTestData(t, db)
	conn := newBotAccessBufconnClient(t, db)
	defer conn.Close()

	accessToken := seedBotAccessToken(t, db, bot.ID)

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+accessToken))
	accessClient := pb.NewBotAccessServiceClient(conn)

	resolved, err := accessClient.ResolveBotUser(ctx, &pb.ResolveBotUserRequest{ExternalUserId: "tg-123"})
	require.NoError(t, err)
	assert.Equal(t, identityUser.ID, resolved.UserId)
	assert.Equal(t, bot.ID, resolved.BotId)
	assert.Equal(t, "tg-123", resolved.ExternalUserId)
	assert.Equal(t, "alice", resolved.ExternalUsername)

	accounts, err := accessClient.ListAccessibleAccounts(ctx, &pb.ListAccessibleAccountsRequest{
		ExternalUserId: "tg-123",
		Platform:       "hoyoverse",
	})
	require.NoError(t, err)
	require.Len(t, accounts.Accounts, 1)
	assert.Equal(t, ref.ID, accounts.Accounts[0].Id)
	assert.Equal(t, "platform-hoyoverse-service", accounts.Accounts[0].PlatformServiceKey)

	ticketResp, err := accessClient.IssueServiceTicket(ctx, &pb.IssueServiceTicketRequest{
		ExternalUserId:  "tg-123",
		BindingId:       ref.ID,
		RequestedScopes: []string{"daily.sign"},
		Audience:        "platform-hoyoverse-service",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, ticketResp.Ticket)
	assert.Equal(t, "platform-hoyoverse-service", ticketResp.Audience)
	assert.Equal(t, ref.ID, ticketResp.Account.Id)

	parsedClaims := &botaccess.ServiceTicketClaims{}
	parsedToken, err := jwt.ParseWithClaims(ticketResp.Ticket, parsedClaims, func(token *jwt.Token) (any, error) {
		return []byte(botAccessServiceTestSigningKey), nil
	})
	require.NoError(t, err)
	require.True(t, parsedToken.Valid)
	assert.Equal(t, "consumer", parsedClaims.ActorType)
	assert.Equal(t, "paigram-bot", parsedClaims.ActorID)
	assert.Equal(t, "paigram-bot", parsedClaims.Consumer)
	assert.Equal(t, bot.ID, parsedClaims.BotID)
	assert.Equal(t, identityUser.ID, parsedClaims.UserID)
	assert.Equal(t, ref.ID, parsedClaims.BindingID)
	assert.Equal(t, ref.ID, parsedClaims.PlatformAccountRefID)
	assert.Equal(t, []string{"daily.sign"}, parsedClaims.Scopes)
	assert.ElementsMatch(t, []string{"platform-hoyoverse-service"}, []string(parsedClaims.Audience))
	assert.WithinDuration(t, ticketResp.ExpiresAt.AsTime(), parsedClaims.ExpiresAt.Time, time.Second)
}

func TestBotAccessServiceRejectsRequestedScopesOutsideGrantedSet(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "bot_access_grpc_scope_reject",
		&model.User{},
		&model.UserEmail{},
		&model.Bot{},
		&model.BotToken{},
		&model.BotIdentity{},
		&model.PlatformAccountRef{},
		&model.BotAccountGrant{},
		&model.PlatformAccountBinding{},
		&model.PlatformAccountProfile{},
		&model.ConsumerGrant{},
	)

	bot, _, ref := seedBotAccessGRPCTestData(t, db)
	grantJSON, err := json.Marshal([]string{"daily.sign"})
	require.NoError(t, err)
	require.NoError(t, db.Model(&model.BotAccountGrant{}).Where("bot_id = ? AND platform_account_ref_id = ?", bot.ID, ref.ID).Update("scopes", string(grantJSON)).Error)

	conn := newBotAccessBufconnClient(t, db)
	defer conn.Close()
	accessToken := seedBotAccessToken(t, db, bot.ID)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+accessToken))
	accessClient := pb.NewBotAccessServiceClient(conn)

	_, err = accessClient.IssueServiceTicket(ctx, &pb.IssueServiceTicketRequest{
		ExternalUserId:  "tg-123",
		BindingId:       ref.ID,
		RequestedScopes: []string{"daily.sign", "notes.write"},
		Audience:        "platform-hoyoverse-service",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestBotAccessServiceRejectsRevokedConsumerGrantOnTicketIssue(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "bot_access_grpc_revoked",
		&model.User{},
		&model.UserEmail{},
		&model.Bot{},
		&model.BotToken{},
		&model.BotIdentity{},
		&model.PlatformAccountRef{},
		&model.BotAccountGrant{},
		&model.PlatformAccountBinding{},
		&model.PlatformAccountProfile{},
		&model.ConsumerGrant{},
	)

	bot, _, ref := seedBotAccessGRPCTestData(t, db)
	var grant model.ConsumerGrant
	require.NoError(t, db.Where("binding_id = ? AND consumer = ?", ref.ID, "paigram-bot").First(&grant).Error)
	grant.Status = model.ConsumerGrantStatusRevoked
	grant.RevokedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
	require.NoError(t, db.Save(&grant).Error)

	conn := newBotAccessBufconnClient(t, db)
	defer conn.Close()
	accessToken := seedBotAccessToken(t, db, bot.ID)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+accessToken))
	accessClient := pb.NewBotAccessServiceClient(conn)

	_, err := accessClient.IssueServiceTicket(ctx, &pb.IssueServiceTicketRequest{
		ExternalUserId:  "tg-123",
		BindingId:       ref.ID,
		RequestedScopes: []string{"daily.sign"},
		Audience:        "platform-hoyoverse-service",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestBotAccessServiceRejectsMissingAuthorization(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "bot_access_grpc_noauth",
		&model.User{},
		&model.UserEmail{},
		&model.Bot{},
		&model.BotToken{},
		&model.BotIdentity{},
		&model.PlatformAccountRef{},
		&model.BotAccountGrant{},
	)

	_, _, _ = seedBotAccessGRPCTestData(t, db)
	conn := newBotAccessBufconnClient(t, db)
	defer conn.Close()

	accessClient := pb.NewBotAccessServiceClient(conn)
	_, err := accessClient.ResolveBotUser(context.Background(), &pb.ResolveBotUserRequest{ExternalUserId: "tg-123"})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func seedBotAccessGRPCTestData(t *testing.T, db *gorm.DB) (model.Bot, model.User, model.PlatformAccountBinding) {
	t.Helper()

	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	require.NoError(t, db.Create(&model.UserEmail{UserID: owner.ID, Email: "owner@example.com", IsPrimary: true}).Error)

	bot := model.Bot{
		ID:          "bot-paigram",
		Name:        "PaiGramBot",
		Description: "test bot",
		Type:        "TELEGRAM",
		Status:      "ACTIVE",
		OwnerUserID: owner.ID,
		APIKey:      "api-key-1",
		APISecret:   "unused-in-this-test",
		Scopes:      `["platform.account:read","platform.ticket:issue"]`,
		Metadata:    `{}`,
	}
	require.NoError(t, db.Create(&bot).Error)

	identityUser := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&identityUser).Error)
	require.NoError(t, db.Create(&model.UserEmail{UserID: identityUser.ID, Email: "alice@example.com", IsPrimary: true}).Error)
	require.NoError(t, db.Create(&model.BotIdentity{
		UserID:           identityUser.ID,
		BotID:            bot.ID,
		ExternalUserID:   "tg-123",
		ExternalUsername: sql.NullString{String: "alice", Valid: true},
		LinkedAt:         time.Now().UTC(),
	}).Error)

	ref := model.PlatformAccountBinding{
		OwnerUserID:        identityUser.ID,
		Platform:           "hoyoverse",
		ExternalAccountKey: sql.NullString{String: "hoyo-account-001", Valid: true},
		PlatformServiceKey: "platform-hoyoverse-service",
		DisplayName:        "Alice Hoyo",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&ref).Error)
	require.NoError(t, db.Create(&model.ConsumerGrant{
		BindingID: ref.ID,
		Consumer:  "paigram-bot",
		Status:    model.ConsumerGrantStatusActive,
		GrantedAt: time.Now().UTC(),
	}).Error)
	require.NoError(t, db.Create(&model.BotAccountGrant{
		UserID:               identityUser.ID,
		BotID:                bot.ID,
		PlatformAccountRefID: ref.ID,
		Scopes:               `["daily.sign","daily.note.read"]`,
		GrantedAt:            time.Now().UTC(),
	}).Error)

	return bot, identityUser, ref
}

func seedBotAccessToken(t *testing.T, db *gorm.DB, botID string) string {
	t.Helper()

	accessToken := "bot-access-token"
	refreshToken := "bot-refresh-token"
	rateLimitTimeWindow := grpcservice.DefaultRateLimitTimeWindow
	rateLimitMax := grpcservice.DefaultRateLimitMax

	require.NoError(t, db.Create(&model.BotToken{
		BotID:               botID,
		AccessTokenHash:     sha256Hex(accessToken),
		RefreshTokenHash:    sha256Hex(refreshToken),
		RateLimitEnabled:    true,
		RateLimitTimeWindow: &rateLimitTimeWindow,
		RateLimitMax:        &rateLimitMax,
		RequestCount:        0,
		Metadata:            `{}`,
		ExpiresAt:           time.Now().Add(time.Hour),
	}).Error)

	return accessToken
}

func sha256Hex(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

func newBotAccessBufconnClient(t *testing.T, db *gorm.DB) *grpc.ClientConn {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer(grpc.ChainUnaryInterceptor(interceptor.NewAuthInterceptor(db, nil, "bot_token:").Unary()))
	pb.RegisterBotAuthServiceServer(grpcServer, grpcservice.NewBotAuthServiceAdapter(grpcservice.NewBotAuthService(db, nil, "bot_token:")))

	group, err := botaccess.NewServiceGroup(db, config.AuthConfig{
		ServiceTicketTTLSeconds: 300,
		ServiceTicketIssuer:     "paigram-account-center",
		ServiceTicketSigningKey: botAccessServiceTestSigningKey,
	})
	require.NoError(t, err)
	pb.RegisterBotAccessServiceServer(grpcServer, grpcservice.NewBotAccessService(&group.AccountRefService, &group.TicketService))

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- grpcServer.Serve(listener)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
		<-serveErrCh
	})

	conn, err := grpc.DialContext(context.Background(), "passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	return conn
}

package service_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"gorm.io/gorm"

	"paigram/internal/cache"
	"paigram/internal/grpc/interceptor"
	pb "paigram/internal/grpc/pb/v1"
	grpcservice "paigram/internal/grpc/service"
	"paigram/internal/model"
	"paigram/internal/testutil"
)

// newBotAuthBufconnClient wires up just the BotAuthService behind the real auth interceptor
// so we can exercise the public-method whitelist and the bot-scoped caller identity.
func newBotAuthBufconnClient(t *testing.T, db *gorm.DB) *grpc.ClientConn {
	t.Helper()
	conn, _ := newBotAuthBufconnClientWithCache(t, db, nil)
	return conn
}

// newBotAuthBufconnClientWithCache is like newBotAuthBufconnClient but injects
// a caller-provided BotTokenCacheStore into the BotAuthService that's
// registered on the gRPC server. Used by reuse-detection tests that need to
// observe cache invalidation as a side effect of token rotation/reuse.
//
// It also returns the underlying *BotAuthService so tests can call into it
// directly when going through the gRPC interceptor would be inconvenient — for
// example, ValidateBotToken is not a publicMethod, so calling it through the
// gRPC client requires authenticating as a bot in metadata, which doesn't
// share state with the registered service's cache. Direct calls bypass that.
func newBotAuthBufconnClientWithCache(t *testing.T, db *gorm.DB, store cache.BotTokenCacheStore) (*grpc.ClientConn, *grpcservice.BotAuthService) {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer(grpc.ChainUnaryInterceptor(interceptor.NewAuthInterceptor(db, nil, "bot_token:").Unary()))

	var core *grpcservice.BotAuthService
	if store != nil {
		core = grpcservice.NewBotAuthServiceWithCache(db, store)
	} else {
		core = grpcservice.NewBotAuthService(db, nil, "bot_token:")
	}
	pb.RegisterBotAuthServiceServer(grpcServer, grpcservice.NewBotAuthServiceAdapter(core))

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

	return conn, core
}

// seedBotAuthOwner creates an owner user with the given primary email and returns the user id.
func seedBotAuthOwner(t *testing.T, db *gorm.DB, email string) uint64 {
	t.Helper()
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	require.NoError(t, db.Create(&model.UserEmail{UserID: owner.ID, Email: email, IsPrimary: true}).Error)
	return owner.ID
}

// seedActiveBotForOwner registers a bot owned by ownerID and seeds an active access token; returns the bearer access token.
func seedActiveBotForOwner(t *testing.T, db *gorm.DB, botID string, ownerID uint64) string {
	t.Helper()
	bot := model.Bot{
		ID:          botID,
		Name:        botID,
		Type:        "TELEGRAM",
		Status:      "ACTIVE",
		OwnerUserID: ownerID,
		APIKey:      "api-key-" + botID,
		APISecret:   "unused-in-this-test",
		Scopes:      `["bot.read","bot.write"]`,
		Metadata:    `{}`,
	}
	require.NoError(t, db.Create(&bot).Error)
	return seedBotAccessToken(t, db, bot.ID)
}

func TestRegisterBot_RejectsUnauthenticated(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "bot_auth_register_noauth",
		&model.User{},
		&model.UserEmail{},
		&model.Bot{},
		&model.BotToken{},
	)
	_ = seedBotAuthOwner(t, db, "alice@example.com")

	conn := newBotAuthBufconnClient(t, db)
	defer conn.Close()
	client := pb.NewBotAuthServiceClient(conn)

	_, err := client.RegisterBot(context.Background(), &pb.RegisterBotRequest{
		Name:       "telegram-bot",
		OwnerEmail: "alice@example.com",
		Type:       pb.BotType_BOT_TYPE_TELEGRAM,
		Scopes:     []string{"bot.read"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRegisterBot_RejectsCrossUserOwner(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "bot_auth_register_cross",
		&model.User{},
		&model.UserEmail{},
		&model.Bot{},
		&model.BotToken{},
	)

	aliceID := seedBotAuthOwner(t, db, "alice@example.com")
	_ = seedBotAuthOwner(t, db, "bob@example.com")
	accessToken := seedActiveBotForOwner(t, db, "bot-alice", aliceID)

	conn := newBotAuthBufconnClient(t, db)
	defer conn.Close()
	client := pb.NewBotAuthServiceClient(conn)
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+accessToken)

	_, err := client.RegisterBot(ctx, &pb.RegisterBotRequest{
		Name:       "telegram-bot",
		OwnerEmail: "bob@example.com",
		Type:       pb.BotType_BOT_TYPE_TELEGRAM,
		Scopes:     []string{"bot.read"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestRegisterBot_RejectsAdminScope(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "bot_auth_register_admin",
		&model.User{},
		&model.UserEmail{},
		&model.Bot{},
		&model.BotToken{},
	)

	aliceID := seedBotAuthOwner(t, db, "alice@example.com")
	accessToken := seedActiveBotForOwner(t, db, "bot-alice-admin", aliceID)

	conn := newBotAuthBufconnClient(t, db)
	defer conn.Close()
	client := pb.NewBotAuthServiceClient(conn)
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+accessToken)

	_, err := client.RegisterBot(ctx, &pb.RegisterBotRequest{
		Name:       "rogue-bot",
		OwnerEmail: "alice@example.com",
		Type:       pb.BotType_BOT_TYPE_TELEGRAM,
		Scopes:     []string{"admin.all"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestRefreshBotToken_ReuseDetectionRevokesFamily(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "bot_auth_refresh_reuse",
		&model.User{},
		&model.UserEmail{},
		&model.Bot{},
		&model.BotToken{},
	)

	// Register an owner + an authenticated bot, then call BotLogin to obtain a real
	// (access, refresh) pair backed by an active bot_tokens row in the same family.
	ownerID := seedBotAuthOwner(t, db, "alice@example.com")
	apiSecret := "test-bot-secret-1234"
	hashedSecretBytes, err := bcrypt.GenerateFromPassword([]byte(apiSecret), bcrypt.MinCost)
	require.NoError(t, err)
	hashedSecret := string(hashedSecretBytes)
	bot := model.Bot{
		ID:          "bot-refresh-reuse",
		Name:        "bot-refresh-reuse",
		Type:        "TELEGRAM",
		Status:      "ACTIVE",
		OwnerUserID: ownerID,
		APIKey:      "api-key-refresh-reuse",
		APISecret:   hashedSecret,
		Scopes:      `["bot.read"]`,
		Metadata:    `{}`,
	}
	require.NoError(t, db.Create(&bot).Error)

	// Wire an in-memory cache fake into the BotAuthService so we can directly
	// observe whether reuse detection invalidates cache entries for every
	// member of the affected family — not just the row whose refresh token
	// triggered the detection.
	fakeCache := newInMemoryBotTokenCache()
	conn, core := newBotAuthBufconnClientWithCache(t, db, fakeCache)
	defer conn.Close()
	client := pb.NewBotAuthServiceClient(conn)

	loginResp, err := client.BotLogin(context.Background(), &pb.BotLoginRequest{
		ApiKey:    bot.APIKey,
		ApiSecret: apiSecret,
	})
	require.NoError(t, err)
	t1Refresh := loginResp.RefreshToken
	t1Access := loginResp.AccessToken
	require.NotEmpty(t, t1Refresh)
	require.NotEmpty(t, t1Access)

	// Capture original family_id (the access-token row that BotLogin just created).
	var initialToken model.BotToken
	require.NoError(t, db.Where("bot_id = ?", bot.ID).Order("id ASC").First(&initialToken).Error)
	familyID := initialToken.FamilyID
	require.NotEmpty(t, familyID, "BotLogin must assign a family_id to the issued token")
	require.Equal(t, "active", initialToken.Status)
	t1AccessHash := initialToken.AccessTokenHash

	// Prime the cache for T1 by calling ValidateBotToken directly on the
	// registered service. We bypass the gRPC client here because
	// ValidateBotToken is not a public method on the auth interceptor — going
	// through the wire would require authenticating as a bot in metadata,
	// which involves a separate BotAuthService instance inside the
	// interceptor that doesn't share our fake cache. Direct calls keep the
	// cache observation honest.
	t1ValidateResp, err := core.ValidateBotToken(context.Background(), &grpcservice.ValidateBotTokenRequest{AccessToken: t1Access})
	require.NoError(t, err)
	require.True(t, t1ValidateResp.Valid)
	require.Eventually(t, func() bool { return fakeCache.hasEntry(t1AccessHash) }, 2*time.Second, 10*time.Millisecond,
		"ValidateBotToken should populate the cache for T1's access hash")

	// Legitimate rotation: T1 -> T2.
	rotateResp, err := client.RefreshBotToken(context.Background(), &pb.RefreshBotTokenRequest{
		RefreshToken: t1Refresh,
	})
	require.NoError(t, err)
	t2Refresh := rotateResp.RefreshToken
	t2Access := rotateResp.AccessToken
	require.NotEmpty(t, t2Refresh)
	require.NotEmpty(t, t2Access)

	// After rotation T1's cache entry must be cleared (otherwise a stale cached
	// validation would let the rotated access token keep working until TTL).
	require.Eventually(t, func() bool { return !fakeCache.hasEntry(t1AccessHash) }, 2*time.Second, 10*time.Millisecond,
		"rotation should invalidate the previous access token's cache entry")
	require.Eventually(t, func() bool { return fakeCache.isRevoked(t1AccessHash) }, 2*time.Second, 10*time.Millisecond,
		"rotation should add the previous access token to the cache revocation set")

	// Look up T2's row so we can target its access hash directly.
	var t2Row model.BotToken
	require.NoError(t, db.Where("family_id = ? AND status = ?", familyID, "active").First(&t2Row).Error)
	t2AccessHash := t2Row.AccessTokenHash
	require.NotEqual(t, t1AccessHash, t2AccessHash)

	// Prime the cache for T2 too — this is the entry that Issue #1 forgot to
	// clear when reuse detection later fires on T1.
	t2ValidateResp, err := core.ValidateBotToken(context.Background(), &grpcservice.ValidateBotTokenRequest{AccessToken: t2Access})
	require.NoError(t, err)
	require.True(t, t2ValidateResp.Valid)
	require.Eventually(t, func() bool { return fakeCache.hasEntry(t2AccessHash) }, 2*time.Second, 10*time.Millisecond,
		"ValidateBotToken should populate the cache for T2's access hash")

	// Re-using T1 must trigger reuse detection and revoke the whole family.
	_, err = client.RefreshBotToken(context.Background(), &pb.RefreshBotTokenRequest{
		RefreshToken: t1Refresh,
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	// All rows in the family must now be marked revoked at the DB layer.
	var familyRows []model.BotToken
	require.NoError(t, db.Where("family_id = ?", familyID).Find(&familyRows).Error)
	require.NotEmpty(t, familyRows)
	for _, row := range familyRows {
		assert.Equal(t, "revoked", row.Status, "row id=%d should be revoked after reuse detection", row.ID)
		assert.True(t, row.RevokedAt.Valid, "row id=%d should have revoked_at set", row.ID)
	}

	// And — the assertion that catches Issue #1 — every family member's cache
	// entry must be invalidated, including T2's, so the attacker's stolen T2
	// access token can't keep validating from the fast path until TTL.
	require.Eventually(t, func() bool { return !fakeCache.hasEntry(t2AccessHash) }, 2*time.Second, 10*time.Millisecond,
		"reuse detection should invalidate cache entries for ALL family members, not just T1")
	require.Eventually(t, func() bool { return fakeCache.isRevoked(t2AccessHash) }, 2*time.Second, 10*time.Millisecond,
		"reuse detection should add every family member's access hash to the cache revocation set")

	// T2 must also fail when used as a refresh token (its row is in the revoked family).
	_, err = client.RefreshBotToken(context.Background(), &pb.RefreshBotTokenRequest{
		RefreshToken: t2Refresh,
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	// And T2's access token must no longer validate — the IsRevoked fast-path
	// in ValidateBotToken must short-circuit on the cache revocation set.
	t2PostResp, err := core.ValidateBotToken(context.Background(), &grpcservice.ValidateBotTokenRequest{AccessToken: t2Access})
	require.NoError(t, err)
	assert.False(t, t2PostResp.Valid, "T2 access token must not validate after its family was revoked")
}

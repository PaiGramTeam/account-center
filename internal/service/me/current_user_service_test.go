package me

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"paigram/internal/model"
	"paigram/internal/sessioncache"
	"paigram/internal/testutil"
)

func setupMeServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	return testutil.OpenMySQLTestDB(t, "me_service",
		&model.User{},
		&model.UserProfile{},
		&model.UserCredential{},
		&model.UserEmail{},
		&model.Role{},
		&model.Permission{},
		&model.UserRole{},
		&model.RolePermission{},
		&model.UserSession{},
		&model.UserTwoFactor{},
		&model.UserDevice{},
		&model.LoginLog{},
		&model.AuditLog{},
	)
}

func TestCurrentUserServiceCreateEmailCreatesVerificationTokenAndExpiry(t *testing.T) {
	db := setupMeServiceTestDB(t)
	service := NewCurrentUserService(db)
	user := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&user).Error)

	created, err := service.CreateEmail(context.Background(), CreateEmailInput{UserID: user.ID, Email: "alt@example.com", VerificationTTL: 2 * time.Hour})
	require.NoError(t, err)
	assert.Equal(t, "alt@example.com", created.Email)
	assert.NotEmpty(t, created.VerificationToken)
	assert.WithinDuration(t, time.Now().UTC().Add(2*time.Hour), created.VerificationExpiresAt, 5*time.Second)

	var stored model.UserEmail
	require.NoError(t, db.First(&stored, created.ID).Error)
	assert.Equal(t, sha256Hex(created.VerificationToken), stored.VerificationToken)
	assert.True(t, regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(stored.VerificationToken))
	assert.True(t, stored.VerificationExpiry.Valid)
}

func TestBuildLoginMethodViewsMarksOnlySingleOAuthCredentialPrimary(t *testing.T) {
	base := time.Now().UTC()
	views := buildLoginMethodViews(model.LoginTypeOAuth, []model.UserCredential{
		{Provider: "github", ProviderAccountID: "github-1", CreatedAt: base.Add(time.Minute)},
		{Provider: "telegram", ProviderAccountID: "telegram-1", CreatedAt: base.Add(2 * time.Minute)},
		{Provider: "google", ProviderAccountID: "google-1", CreatedAt: base},
	})

	require.Len(t, views, 3)
	assert.Equal(t, "google", views[0].Provider)
	assert.True(t, views[0].IsPrimary)
	assert.Equal(t, "github", views[1].Provider)
	assert.False(t, views[1].IsPrimary)
	assert.Equal(t, "telegram", views[2].Provider)
	assert.False(t, views[2].IsPrimary)
}

func TestBuildLoginMethodViewsOrdersSameCreatedAtDeterministically(t *testing.T) {
	createdAt := time.Now().UTC()
	views := buildLoginMethodViews(model.LoginTypeOAuth, []model.UserCredential{
		{ID: 20, Provider: "telegram", ProviderAccountID: "telegram-1", CreatedAt: createdAt},
		{ID: 10, Provider: "github", ProviderAccountID: "github-1", CreatedAt: createdAt},
		{ID: 30, Provider: "google", ProviderAccountID: "google-1", CreatedAt: createdAt},
	})

	require.Len(t, views, 3)
	assert.Equal(t, []string{"github", "telegram", "google"}, []string{views[0].Provider, views[1].Provider, views[2].Provider})
	assert.True(t, views[0].IsPrimary)
	assert.False(t, views[1].IsPrimary)
	assert.False(t, views[2].IsPrimary)
}

func TestDeleteLoginMethodGuardAllowsSecondaryOAuthButProtectsPrimary(t *testing.T) {
	credentials := []model.UserCredential{
		{Provider: "github", ProviderAccountID: "github-1", CreatedAt: time.Now().UTC().Add(time.Minute)},
		{Provider: "email", ProviderAccountID: "user@example.com", CreatedAt: time.Now().UTC().Add(2 * time.Minute)},
		{Provider: "google", ProviderAccountID: "google-1", CreatedAt: time.Now().UTC()},
	}

	require.NoError(t, validateDeleteLoginMethod(model.LoginTypeOAuth, credentials, "github"))
	require.ErrorIs(t, validateDeleteLoginMethod(model.LoginTypeOAuth, credentials, "google"), ErrCannotUnbindPrimaryLogin)
}

func TestCurrentUserServiceDeleteLoginMethodAllowsSecondaryOAuthButProtectsPrimary(t *testing.T) {
	db := setupMeServiceTestDB(t)
	service := NewCurrentUserService(db)
	user := model.User{PrimaryLoginType: model.LoginTypeOAuth, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&user).Error)
	google := model.UserCredential{UserID: user.ID, Provider: "google", ProviderAccountID: "google-1"}
	github := model.UserCredential{UserID: user.ID, Provider: "github", ProviderAccountID: "github-1"}
	email := model.UserCredential{UserID: user.ID, Provider: "email", ProviderAccountID: "user@example.com"}
	require.NoError(t, db.Create(&google).Error)
	require.NoError(t, db.Create(&github).Error)
	require.NoError(t, db.Create(&email).Error)

	require.NoError(t, service.DeleteLoginMethod(context.Background(), user.ID, "github"))
	require.ErrorIs(t, service.DeleteLoginMethod(context.Background(), user.ID, "google"), ErrCannotUnbindPrimaryLogin)

	var githubCount int64
	require.NoError(t, db.Model(&model.UserCredential{}).Where("user_id = ? AND provider = ?", user.ID, "github").Count(&githubCount).Error)
	assert.Zero(t, githubCount)
	var googleCount int64
	require.NoError(t, db.Model(&model.UserCredential{}).Where("user_id = ? AND provider = ?", user.ID, "google").Count(&googleCount).Error)
	assert.EqualValues(t, 1, googleCount)
}

func TestCurrentUserServiceDeleteEmailPromotesRemainingEmailToPrimary(t *testing.T) {
	db := setupMeServiceTestDB(t)
	service := NewCurrentUserService(db)
	user := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&user).Error)
	primaryVerifiedAt := sql.NullTime{Time: time.Now().UTC().Add(-time.Hour), Valid: true}
	primary := model.UserEmail{UserID: user.ID, Email: "primary@example.com", IsPrimary: true, VerifiedAt: primaryVerifiedAt}
	secondary := model.UserEmail{UserID: user.ID, Email: "secondary@example.com"}
	require.NoError(t, db.Create(&primary).Error)
	require.NoError(t, db.Create(&secondary).Error)

	err := service.DeleteEmail(context.Background(), user.ID, primary.ID)
	require.NoError(t, err)

	var deleted model.UserEmail
	assert.Error(t, db.First(&deleted, primary.ID).Error)
	var remaining model.UserEmail
	require.NoError(t, db.First(&remaining, secondary.ID).Error)
	assert.True(t, remaining.IsPrimary)
}

func TestCurrentUserServiceVerifyEmailRefreshesVerificationTokenAndExpiry(t *testing.T) {
	db := setupMeServiceTestDB(t)
	service := NewCurrentUserService(db)
	user := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&user).Error)
	oldPlainToken := "old-token"
	email := model.UserEmail{
		UserID:             user.ID,
		Email:              "pending@example.com",
		VerificationToken:  sha256Hex(oldPlainToken),
		VerificationExpiry: sql.NullTime{Time: time.Now().UTC().Add(-time.Hour), Valid: true},
		UpdatedAt:          time.Now().UTC().Add(-2 * time.Minute),
	}
	require.NoError(t, db.Create(&email).Error)
	require.NoError(t, db.Model(&email).Update("updated_at", email.UpdatedAt).Error)

	view, err := service.VerifyEmail(context.Background(), VerifyEmailInput{UserID: user.ID, EmailID: email.ID, VerificationTTL: 3 * time.Hour})
	require.NoError(t, err)
	assert.NotEmpty(t, view.VerificationExpiresAt)

	var stored model.UserEmail
	require.NoError(t, db.First(&stored, email.ID).Error)
	assert.NotEqual(t, sha256Hex(oldPlainToken), stored.VerificationToken)
	assert.True(t, regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(stored.VerificationToken))
	assert.True(t, stored.VerificationExpiry.Valid)
	assert.WithinDuration(t, time.Now().UTC().Add(3*time.Hour), stored.VerificationExpiry.Time, 5*time.Second)
}

func sha256Hex(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

func TestCurrentUserServiceGetDashboardSummaryAggregatesBindingsProfilesAndConsumers(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "me_dashboard_summary",
		&model.User{},
		&model.PlatformAccountBinding{},
		&model.PlatformAccountProfile{},
		&model.ConsumerGrant{},
	)
	service := NewCurrentUserService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	other := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	require.NoError(t, db.Create(&other).Error)

	activeBinding := model.PlatformAccountBinding{OwnerUserID: owner.ID, Platform: "mihomo", PlatformServiceKey: "mihomo-main", DisplayName: "Primary", Status: model.PlatformAccountBindingStatusActive}
	invalidBinding := model.PlatformAccountBinding{OwnerUserID: owner.ID, Platform: "mihomo", PlatformServiceKey: "mihomo-main", DisplayName: "Expired", Status: model.PlatformAccountBindingStatusCredentialInvalid}
	refreshBinding := model.PlatformAccountBinding{OwnerUserID: owner.ID, Platform: "mihomo", PlatformServiceKey: "mihomo-main", DisplayName: "Refresh", Status: model.PlatformAccountBindingStatusRefreshRequired}
	otherBinding := model.PlatformAccountBinding{OwnerUserID: other.ID, Platform: "mihomo", PlatformServiceKey: "mihomo-main", DisplayName: "Other", Status: model.PlatformAccountBindingStatusActive}
	require.NoError(t, db.Create(&activeBinding).Error)
	require.NoError(t, db.Create(&invalidBinding).Error)
	require.NoError(t, db.Create(&refreshBinding).Error)
	require.NoError(t, db.Create(&otherBinding).Error)

	profiles := []model.PlatformAccountProfile{
		{BindingID: activeBinding.ID, PlatformProfileKey: "profile-1", GameBiz: "hk4e_global", Region: "os_asia", PlayerUID: "1001", Nickname: "One"},
		{BindingID: invalidBinding.ID, PlatformProfileKey: "profile-2", GameBiz: "hk4e_global", Region: "os_euro", PlayerUID: "1002", Nickname: "Two"},
		{BindingID: otherBinding.ID, PlatformProfileKey: "profile-3", GameBiz: "hk4e_global", Region: "os_usa", PlayerUID: "2001", Nickname: "Other"},
	}
	require.NoError(t, db.Create(&profiles).Error)

	grants := []model.ConsumerGrant{
		{BindingID: activeBinding.ID, Consumer: "paigram-bot", Status: model.ConsumerGrantStatusActive},
		{BindingID: invalidBinding.ID, Consumer: "paigram-bot-secondary", Status: model.ConsumerGrantStatusActive},
		{BindingID: refreshBinding.ID, Consumer: "paigram-bot-disabled", Status: model.ConsumerGrantStatusRevoked},
		{BindingID: otherBinding.ID, Consumer: "other-user-bot", Status: model.ConsumerGrantStatusActive},
	}
	require.NoError(t, db.Create(&grants).Error)

	summary, err := service.GetDashboardSummary(context.Background(), owner.ID)
	require.NoError(t, err)
	assert.Equal(t, &DashboardSummaryView{
		TotalBindings:           3,
		ActiveBindings:          1,
		InvalidBindings:         1,
		RefreshRequiredBindings: 1,
		TotalProfiles:           2,
		EnabledConsumers:        2,
	}, summary)
}

func TestCurrentUserServiceGetCurrentUserViewIncludesRolesAndPermissions(t *testing.T) {
	db := setupMeServiceTestDB(t)
	service := NewCurrentUserService(db)
	user := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&user).Error)
	require.NoError(t, db.Create(&model.UserProfile{UserID: user.ID, DisplayName: "Admin Operator", Locale: "zh-CN"}).Error)
	require.NoError(t, db.Create(&model.UserEmail{UserID: user.ID, Email: "admin@example.com", IsPrimary: true}).Error)

	role := model.Role{Name: "admin", DisplayName: "管理员"}
	permission := model.Permission{Name: "platform_account:read", Resource: model.ResourcePlatformAccount, Action: model.ActionRead}
	require.NoError(t, db.Create(&role).Error)
	require.NoError(t, db.Create(&permission).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: user.ID, RoleID: role.ID}).Error)
	require.NoError(t, db.Create(&model.RolePermission{RoleID: role.ID, PermissionID: permission.ID}).Error)

	view, err := service.GetCurrentUserView(context.Background(), user.ID)
	require.NoError(t, err)
	require.Equal(t, user.ID, view.ID)
	require.Equal(t, []string{"admin"}, view.Roles)
	require.Equal(t, []string{"platform_account:read"}, view.Permissions)
}

func TestSessionServiceListSessionsMarksCurrentAndLoadsDevice(t *testing.T) {
	db := setupMeServiceTestDB(t)
	service := NewSessionService(db, sessioncache.NewNoopStore())
	user := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&user).Error)
	accessToken := "current-access-token"
	currentHash := hashBearerToken(accessToken)
	now := time.Now().UTC()
	session := model.UserSession{
		UserID:           user.ID,
		AccessTokenHash:  currentHash,
		RefreshTokenHash: "refresh-hash-1",
		AccessExpiry:     now.Add(time.Hour),
		RefreshExpiry:    now.Add(24 * time.Hour),
		UserAgent:        "Mozilla/5.0",
		ClientIP:         "127.0.0.1",
		CreatedAt:        now.Add(-time.Minute),
	}
	require.NoError(t, db.Create(&session).Error)
	device := model.UserDevice{UserID: user.ID, DeviceID: buildDeviceID(session.UserAgent, session.ClientIP), DeviceName: "Laptop", DeviceType: "desktop", Location: "Localhost", LastActiveAt: now}
	require.NoError(t, db.Create(&device).Error)

	views, err := service.ListSessions(context.Background(), user.ID, accessToken)
	require.NoError(t, err)
	require.Len(t, views, 1)
	assert.True(t, views[0].IsCurrent)
	assert.Equal(t, "Laptop", views[0].DeviceName)
	assert.Equal(t, "Localhost", views[0].Location)
}

func TestSecurityServiceGetOverviewSummarizesCurrentUserSecurityState(t *testing.T) {
	db := setupMeServiceTestDB(t)
	service := NewSecurityService(db, sessioncache.NewNoopStore())
	user := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&user).Error)
	require.NoError(t, db.Create(&model.UserTwoFactor{UserID: user.ID, Secret: "secret", BackupCodes: "[]", EnabledAt: time.Now().UTC()}).Error)
	require.NoError(t, db.Create(&model.UserSession{UserID: user.ID, AccessTokenHash: "access", RefreshTokenHash: "refresh", AccessExpiry: time.Now().UTC().Add(time.Hour), RefreshExpiry: time.Now().UTC().Add(24 * time.Hour)}).Error)
	require.NoError(t, db.Create(&model.UserDevice{UserID: user.ID, DeviceID: "device-1", LastActiveAt: time.Now().UTC()}).Error)
	require.NoError(t, db.Create(&model.LoginLog{UserID: user.ID, Status: "failed", CreatedAt: time.Now().UTC().Add(-time.Hour)}).Error)
	require.NoError(t, db.Create(&model.LoginLog{UserID: user.ID, Status: "success", IP: "127.0.0.1", Device: "Browser", Location: "Earth", CreatedAt: time.Now().UTC()}).Error)

	overview, err := service.GetOverview(context.Background(), user.ID)
	require.NoError(t, err)
	assert.True(t, overview.TwoFactorEnabled)
	assert.EqualValues(t, 1, overview.ActiveSessionCount)
	assert.EqualValues(t, 1, overview.DeviceCount)
	assert.EqualValues(t, 1, overview.FailedLoginsLast30Days)
	assert.Equal(t, "127.0.0.1", overview.LastLoginIP)
	assert.Equal(t, "Browser", overview.LastLoginDevice)
	assert.Equal(t, "Earth", overview.LastLoginLocation)
}

func TestSecurityServiceUpdatePasswordRehashesPasswordAndRevokesOtherSessions(t *testing.T) {
	db := setupMeServiceTestDB(t)
	service := NewSecurityService(db, sessioncache.NewNoopStore())
	user := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&user).Error)
	oldHash, err := bcrypt.GenerateFromPassword([]byte("old-password"), defaultBcryptCost)
	require.NoError(t, err)
	credential := model.UserCredential{UserID: user.ID, Provider: "email", ProviderAccountID: "user@example.com", PasswordHash: string(oldHash)}
	require.NoError(t, db.Create(&credential).Error)
	currentToken := "current-token"
	currentSession := model.UserSession{UserID: user.ID, AccessTokenHash: hashBearerToken(currentToken), RefreshTokenHash: "refresh-current", AccessExpiry: time.Now().UTC().Add(time.Hour), RefreshExpiry: time.Now().UTC().Add(24 * time.Hour)}
	otherSession := model.UserSession{UserID: user.ID, AccessTokenHash: "other-access", RefreshTokenHash: "refresh-other", AccessExpiry: time.Now().UTC().Add(time.Hour), RefreshExpiry: time.Now().UTC().Add(24 * time.Hour)}
	require.NoError(t, db.Create(&currentSession).Error)
	require.NoError(t, db.Create(&otherSession).Error)

	err = service.UpdatePassword(context.Background(), UpdatePasswordInput{UserID: user.ID, OldPassword: "old-password", NewPassword: "new-password", RevokeOtherSessions: true, CurrentAccessToken: currentToken, ClientIP: "127.0.0.1", UserAgent: "go-test"})
	require.NoError(t, err)

	var updated model.UserCredential
	require.NoError(t, db.First(&updated, credential.ID).Error)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(updated.PasswordHash), []byte("new-password")))
	var revoked model.UserSession
	require.NoError(t, db.First(&revoked, otherSession.ID).Error)
	assert.True(t, revoked.RevokedAt.Valid)
	assert.Equal(t, "password_changed", revoked.RevokedReason)
	var current model.UserSession
	require.NoError(t, db.First(&current, currentSession.ID).Error)
	assert.False(t, current.RevokedAt.Valid)
	var auditCount int64
	require.NoError(t, db.Model(&model.AuditLog{}).Where("user_id = ? AND action = ?", user.ID, "password_change").Count(&auditCount).Error)
	assert.EqualValues(t, 1, auditCount)
}

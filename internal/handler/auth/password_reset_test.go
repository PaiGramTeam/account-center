package auth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/model"
	"paigram/internal/sessioncache"
)

// inMemorySessionCache is a test-only in-process Store. We need to assert
// that V15 password-reset writes per-session revocation markers to the
// cache, and the production NoopStore swallows everything. Rather than
// stand up a real Redis (or pull miniredis as a new dependency) we mirror
// the small fake used for the bot-token tests in
// internal/grpc/service/bot_auth_fake_cache_test.go.
//
// This fake intentionally implements only the surface revokeAllUserSessions
// touches: Set/Get/Delete of generic keys (revoked-marker + current-access-
// hash). Methods unused by the test return redis.Nil/no-op so the rest of
// the handler doesn't trip while the test runs.
type inMemorySessionCache struct {
	mu      sync.Mutex
	entries map[string][]byte
}

func newInMemorySessionCache() *inMemorySessionCache {
	return &inMemorySessionCache{entries: make(map[string][]byte)}
}

func (c *inMemorySessionCache) SaveSession(_ context.Context, _ *model.UserSession) error {
	return nil
}

func (c *inMemorySessionCache) SaveSessionWithTokens(_ context.Context, _ *model.UserSession, _, _ string) error {
	return nil
}

func (c *inMemorySessionCache) RemoveTokens(_ context.Context, _, _ string) error {
	return nil
}

func (c *inMemorySessionCache) GetSessionID(_ context.Context, _ sessioncache.TokenType, _ string) (uint64, error) {
	return 0, redis.Nil
}

func (c *inMemorySessionCache) GetSessionData(_ context.Context, _ sessioncache.TokenType, _ string) (*sessioncache.SessionData, error) {
	return nil, redis.Nil
}

func (c *inMemorySessionCache) MarkRevoked(_ context.Context, _ sessioncache.TokenType, _ string, _ time.Duration) error {
	return nil
}

func (c *inMemorySessionCache) IsRevoked(_ context.Context, _ sessioncache.TokenType, _ string) (bool, error) {
	return false, nil
}

func (c *inMemorySessionCache) IncrementCounter(_ context.Context, _ string, _ time.Duration) (int64, error) {
	return 0, nil
}

func (c *inMemorySessionCache) GetTTL(_ context.Context, _ string) (time.Duration, error) {
	return 0, nil
}

func (c *inMemorySessionCache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
	return nil
}

func (c *inMemorySessionCache) Set(_ context.Context, key string, value []byte, _ time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	stored := append([]byte(nil), value...)
	c.entries[key] = stored
	return nil
}

func (c *inMemorySessionCache) Get(_ context.Context, key string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.entries[key]
	if !ok {
		return nil, redis.Nil
	}
	return append([]byte(nil), v...), nil
}

func (c *inMemorySessionCache) hasKey(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.entries[key]
	return ok
}

func TestForgotPassword_ExistingEmail_CreatesResetToken(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)
	createTestUser(t, db, "reset@example.com", "Password123!", true)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/forgot-password", handler.ForgotPassword)

	body, err := json.Marshal(ForgotPasswordRequest{Email: "reset@example.com"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resetToken model.PasswordResetToken
	require.NoError(t, db.Where("used_at IS NULL").First(&resetToken).Error)
	assert.NotEmpty(t, resetToken.Token)
	assert.WithinDuration(t, time.Now().Add(time.Hour), resetToken.ExpiresAt, 5*time.Second)
}

func TestResetPassword_UpdatesEmailCredentialAndRevokesSessions(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)
	user := createTestUser(t, db, "reset@example.com", "OldPassword123!", true)

	resetToken := model.PasswordResetToken{
		UserID:    user.ID,
		Token:     hashToken("reset-token"),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, db.Create(&resetToken).Error)

	session := model.UserSession{
		UserID:           user.ID,
		AccessTokenHash:  hashToken("access-token"),
		RefreshTokenHash: hashToken("refresh-token"),
		AccessExpiry:     time.Now().Add(time.Hour),
		RefreshExpiry:    time.Now().Add(24 * time.Hour),
		UserAgent:        "PasswordResetTest/1.0",
		ClientIP:         "127.0.0.1",
	}
	require.NoError(t, db.Create(&session).Error)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/reset-password", handler.ResetPassword)

	body, err := json.Marshal(ResetPasswordRequest{
		Token:       "reset-token",
		NewPassword: "NewPassword456!",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var credential model.UserCredential
	require.NoError(t, db.Where("user_id = ? AND provider = ?", user.ID, string(model.LoginTypeEmail)).First(&credential).Error)
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(credential.PasswordHash), []byte("NewPassword456!")))
	assert.Error(t, bcrypt.CompareHashAndPassword([]byte(credential.PasswordHash), []byte("OldPassword123!")))

	var usedToken model.PasswordResetToken
	require.NoError(t, db.First(&usedToken, resetToken.ID).Error)
	assert.True(t, usedToken.UsedAt.Valid)

	// V15: sessions are no longer DELETEd outright; they're UPDATEd with
	// revoked_at + revoked_reason so we keep the audit trail. The total
	// row count is therefore unchanged but every row must now have a
	// non-NULL revoked_at.
	var totalSessions, revokedSessions int64
	require.NoError(t, db.Model(&model.UserSession{}).Where("user_id = ?", user.ID).Count(&totalSessions).Error)
	require.NoError(t, db.Model(&model.UserSession{}).Where("user_id = ? AND revoked_at IS NOT NULL", user.ID).Count(&revokedSessions).Error)
	assert.Equal(t, int64(1), totalSessions, "row preserved for forensic value")
	assert.Equal(t, totalSessions, revokedSessions, "every session must be flagged revoked")

	var deviceCount int64
	require.NoError(t, db.Model(&model.UserDevice{}).Where("user_id = ?", user.ID).Count(&deviceCount).Error)
	assert.Zero(t, deviceCount)
}

func TestForgotPassword_UnknownEmail_ReturnsGenericResponse(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/forgot-password", handler.ForgotPassword)

	body, err := json.Marshal(ForgotPasswordRequest{Email: "missing@example.com"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var tokens int64
	require.NoError(t, db.Model(&model.PasswordResetToken{}).Count(&tokens).Error)
	assert.Zero(t, tokens)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, "if the email exists, a password reset link has been sent", data["message"])
}

func TestResetPassword_InvalidToken_ReturnsBadRequest(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)
	createTestUser(t, db, "reset@example.com", "OldPassword123!", true)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/reset-password", handler.ResetPassword)

	body, err := json.Marshal(ResetPasswordRequest{
		Token:       "unknown-token",
		NewPassword: "NewPassword456!",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errorData := resp["error"].(map[string]any)
	assert.Equal(t, "INVALID_TOKEN", errorData["code"])
}

func TestResetPassword_UsedToken_IsRejected(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)
	user := createTestUser(t, db, "reset@example.com", "OldPassword123!", true)

	resetToken := model.PasswordResetToken{
		UserID:    user.ID,
		Token:     hashToken("used-token"),
		ExpiresAt: time.Now().Add(time.Hour),
		UsedAt: sql.NullTime{
			Time:  time.Now(),
			Valid: true,
		},
	}
	require.NoError(t, db.Create(&resetToken).Error)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/reset-password", handler.ResetPassword)

	body, err := json.Marshal(ResetPasswordRequest{
		Token:       "used-token",
		NewPassword: "NewPassword456!",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errorData := resp["error"].(map[string]any)
	assert.Equal(t, "INVALID_TOKEN", errorData["code"])
}

// recordedResetEmail is captured by the test seam so we can assert what URL
// the handler hands to the email layer.
type recordedResetEmail struct {
	mu      sync.Mutex
	calls   int
	to      string
	token   string
	baseURL string
}

func (r *recordedResetEmail) capture() func(ctx context.Context, to, token, baseURL string) error {
	return func(_ context.Context, to, token, baseURL string) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.calls++
		r.to = to
		r.token = token
		r.baseURL = baseURL
		return nil
	}
}

// waitFor polls cond up to total, returning true when cond is satisfied. The
// password-reset handler dispatches its email send in a goroutine to keep
// response latency uniform regardless of whether the email is real or not,
// so tests need a brief settling window.
func waitFor(total time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(total)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

func TestForgotPassword_BaseURLNotFromOriginHeader(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)
	handler.frontendCfg = config.FrontendConfig{BaseURL: "https://app.example.com"}
	rec := &recordedResetEmail{}
	handler.sendPasswordResetEmail = rec.capture()
	createTestUser(t, db, "v2@example.com", "Password123!", true)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/forgot-password", handler.ForgotPassword)

	body, err := json.Marshal(ForgotPasswordRequest{Email: "v2@example.com"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// SECURITY: this header MUST NOT influence the reset URL — that's the
	// V2 host-header injection vulnerability we are guarding against.
	req.Header.Set("Origin", "https://attacker.example")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	require.True(t, waitFor(time.Second, func() bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return rec.calls == 1
	}), "expected exactly one password-reset email dispatch")

	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Equal(t, "https://app.example.com", rec.baseURL)
	assert.NotContains(t, rec.baseURL, "attacker.example")
	assert.Equal(t, "v2@example.com", rec.to)
	assert.NotEmpty(t, rec.token)
}

func TestForgotPassword_NoEmailWhenBaseURLEmpty(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)
	// Empty BaseURL — fail-closed: no email sent, no fallback to Origin.
	handler.frontendCfg = config.FrontendConfig{BaseURL: ""}
	rec := &recordedResetEmail{}
	handler.sendPasswordResetEmail = rec.capture()
	createTestUser(t, db, "v2-empty@example.com", "Password123!", true)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/forgot-password", handler.ForgotPassword)

	body, err := json.Marshal(ForgotPasswordRequest{Email: "v2-empty@example.com"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://attacker.example")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Generic 200 even though config is broken — don't leak internals.
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Wait briefly, then assert no dispatch happened.
	time.Sleep(50 * time.Millisecond)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Zero(t, rec.calls, "no email should be dispatched when BaseURL is empty")
}

func TestForgotPassword_TrailingSlashTrimmedFromBaseURL(t *testing.T) {
	// Defensive: configs sometimes have trailing slashes. Trimming is part of
	// the V2 fix so the resulting URL doesn't end up with "//reset-password".
	db := setupTestDB(t)
	handler := setupTestHandler(db)
	handler.frontendCfg = config.FrontendConfig{BaseURL: "https://app.example.com/"}
	rec := &recordedResetEmail{}
	handler.sendPasswordResetEmail = rec.capture()
	createTestUser(t, db, "v2-slash@example.com", "Password123!", true)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/forgot-password", handler.ForgotPassword)

	body, err := json.Marshal(ForgotPasswordRequest{Email: "v2-slash@example.com"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	require.True(t, waitFor(time.Second, func() bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return rec.calls == 1
	}))
	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Equal(t, "https://app.example.com", rec.baseURL)
	assert.False(t, strings.HasSuffix(rec.baseURL, "/"))
}

// TestResetPassword_InvalidatesActiveAccessTokensImmediately is the V15
// contract: when a password is reset, every active session for that user
// must become unusable IMMEDIATELY — not "eventually after the access-token
// TTL expires". The middleware's cache fast path (internal/middleware/auth.go)
// already consults sessioncache.RevokedSessionMarkerKey on a cache hit, so
// the gap is on the writer side: revokeAllUserSessions previously DELETEd
// rows but never wrote the per-session marker, leaving any cached
// access-token payload usable until its TTL expired.
//
// The test primes two sessions in the DB, swaps in an in-memory cache,
// runs the password-reset transaction's revocation step, and asserts that
// for each session the RevokedSessionMarkerKey is present in the cache.
// It also asserts that the DB rows are now flagged revoked (option ii:
// UPDATE-with-revoked_at, preserving an audit trail; option i — outright
// DELETE — was an acceptable alternative but loses forensic value).
//
// Failing-then-passing TDD: with the pre-V15 implementation this test
// fails because the marker keys are never written, even though the DB
// rows are deleted.
func TestResetPassword_InvalidatesActiveAccessTokensImmediately(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)
	cache := newInMemorySessionCache()
	handler.sessionCache = cache

	user := createTestUser(t, db, "v15@example.com", "OldPassword123!", true)

	// Prime two sessions: refresh expiries are in the future so the
	// RevokedSessionMarkerTTL helper produces a non-zero TTL, mirroring
	// real production state where a user has at least one live access
	// token at the moment of password reset.
	now := time.Now().UTC()
	sessionA := model.UserSession{
		UserID:           user.ID,
		AccessTokenHash:  hashToken("v15-access-a"),
		RefreshTokenHash: hashToken("v15-refresh-a"),
		AccessExpiry:     now.Add(15 * time.Minute),
		RefreshExpiry:    now.Add(7 * 24 * time.Hour),
		UserAgent:        "V15Test/1.0",
		ClientIP:         "127.0.0.1",
	}
	require.NoError(t, db.Create(&sessionA).Error)

	sessionB := model.UserSession{
		UserID:           user.ID,
		AccessTokenHash:  hashToken("v15-access-b"),
		RefreshTokenHash: hashToken("v15-refresh-b"),
		AccessExpiry:     now.Add(15 * time.Minute),
		RefreshExpiry:    now.Add(7 * 24 * time.Hour),
		UserAgent:        "V15Test/2.0",
		ClientIP:         "127.0.0.2",
	}
	require.NoError(t, db.Create(&sessionB).Error)

	// Pre-populate the current-access-hash markers that
	// cacheStoreSessionWithTokens would have written when these sessions
	// were issued. Without this, the post-revoke "marker is cleared"
	// assertion would tautologically pass against a never-written key.
	primedAccessHashTTL := time.Hour
	require.NoError(t, cache.Set(context.Background(), sessioncache.CurrentAccessTokenHashKey(sessionA.ID), []byte(sessionA.AccessTokenHash), primedAccessHashTTL))
	require.NoError(t, cache.Set(context.Background(), sessioncache.CurrentAccessTokenHashKey(sessionB.ID), []byte(sessionB.AccessTokenHash), primedAccessHashTTL))

	// Drive the revocation through the same two-step pattern the
	// ResetPassword handler uses: revokeAllUserSessions does DB-only work
	// inside the transaction and returns the snapshot; the caller then
	// publishes cache markers AFTER the transaction commits. This
	// ordering matters — writing markers inside the closure risks a
	// stray marker on rollback that would lock the user out of the cache
	// fast path (see revokeAllUserSessions doc + middleware/auth.go:88).
	var revokedSnapshots []model.UserSession
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		snapshots, err := handler.revokeAllUserSessions(tx, user.ID)
		if err != nil {
			return err
		}
		revokedSnapshots = snapshots

		// Pre-commit invariant: cache markers must NOT be present yet,
		// and the primed current-access-hash markers must still be in
		// place. A failure here would mean revokeAllUserSessions wrote
		// to the cache from inside the transaction, reintroducing the
		// stray-marker-on-rollback bug the V15 follow-up was meant to
		// fix.
		assert.False(t, cache.hasKey(sessioncache.RevokedSessionMarkerKey(sessionA.ID)),
			"revokeAllUserSessions must not write cache markers inside the transaction")
		assert.False(t, cache.hasKey(sessioncache.RevokedSessionMarkerKey(sessionB.ID)),
			"revokeAllUserSessions must not write cache markers inside the transaction")
		assert.True(t, cache.hasKey(sessioncache.CurrentAccessTokenHashKey(sessionA.ID)),
			"revokeAllUserSessions must not clear current-access-hash markers inside the transaction")
		assert.True(t, cache.hasKey(sessioncache.CurrentAccessTokenHashKey(sessionB.ID)),
			"revokeAllUserSessions must not clear current-access-hash markers inside the transaction")
		return nil
	}))
	require.Len(t, revokedSnapshots, 2)
	handler.invalidateRevokedSessionsCache(context.Background(), revokedSnapshots)

	// V15 contract: the revocation marker keyed by session ID is present
	// for every previously-active session. The middleware's cache fast
	// path consults this marker before honouring a cached token payload,
	// so writing it closes the cache-bypass window — even tokens still
	// living in the cache become unusable IMMEDIATELY.
	assert.True(t, cache.hasKey(sessioncache.RevokedSessionMarkerKey(sessionA.ID)),
		"expected revoked-session marker for sessionA in cache (cache fast-path bypass open without it)")
	assert.True(t, cache.hasKey(sessioncache.RevokedSessionMarkerKey(sessionB.ID)),
		"expected revoked-session marker for sessionB in cache")

	// The current-access-hash marker must be cleared so that a stale
	// cached payload pinned to the old hash also fails the
	// "currentAccessHash" equality check in the middleware. This mirrors
	// the cleanup the refresh/logout paths already perform via
	// clearCurrentAccessHashMarker.
	assert.False(t, cache.hasKey(sessioncache.CurrentAccessTokenHashKey(sessionA.ID)),
		"current-access-hash marker for sessionA should be cleared on password-reset")
	assert.False(t, cache.hasKey(sessioncache.CurrentAccessTokenHashKey(sessionB.ID)),
		"current-access-hash marker for sessionB should be cleared on password-reset")

	// Option-(ii) audit: the DB rows are now marked revoked (with a
	// revoked_reason), not deleted outright. Loose-coupling check — we
	// don't pin the exact reason string here beyond it being non-empty —
	// to leave room for future refinement without breaking the test.
	var revokedCount int64
	require.NoError(t, db.Model(&model.UserSession{}).
		Where("user_id = ? AND revoked_at IS NOT NULL", user.ID).
		Count(&revokedCount).Error)
	assert.Equal(t, int64(2), revokedCount, "both sessions should be flagged revoked in the DB")

	var refreshed model.UserSession
	require.NoError(t, db.First(&refreshed, sessionA.ID).Error)
	assert.NotEmpty(t, refreshed.RevokedReason, "revoked_reason should be populated for forensic value")

	// Devices for the user are still wiped — losing trust on a password
	// reset is intentional (forces 2FA re-prompt next login).
	var deviceCount int64
	require.NoError(t, db.Model(&model.UserDevice{}).Where("user_id = ?", user.ID).Count(&deviceCount).Error)
	assert.Zero(t, deviceCount)
}

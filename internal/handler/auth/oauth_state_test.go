package auth

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"paigram/internal/middleware"
	"paigram/internal/model"
)

// callbackContext builds a minimal gin.Context with the supplied IP and UA
// for tests that exercise the V23 OAuth-state binding checks. We deliberately
// hand-craft RemoteAddr rather than use httptest.NewRequest defaults so the
// IP is explicit per-test and visible in the test source.
func callbackContext(t *testing.T, w *httptest.ResponseRecorder, body, remoteIPPort, userAgent string) *gin.Context {
	t.Helper()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/telegram/callback", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	req.RemoteAddr = remoteIPPort
	c.Request = req
	c.Params = gin.Params{{Key: "provider", Value: "telegram"}}
	return c
}

func TestOAuthCallback_RejectsStateFromDifferentIP(t *testing.T) {
	db := setupTestDB(t)
	ensureUserOAuthStatesTable(t, db)
	h := setupOAuthTestHandler(t, db)

	// Login-purpose state (no auth required) so the test isolates the V23
	// IP-binding check from the bind-purpose authorization logic.
	state := model.UserOAuthState{
		Provider:     "telegram",
		State:        "v23-ip-mismatch",
		Purpose:      string(model.OAuthPurposeLogin),
		RedirectTo:   "https://app.example.com/auth/callback",
		Nonce:        "expected-nonce",
		CodeVerifier: "expected-verifier",
		ClientIP:     "1.2.3.4",
		UserAgent:    "TestAgent/1.0",
		ExpiresAt:    time.Now().UTC().Add(5 * time.Minute),
	}
	require.NoError(t, db.Create(&state).Error)

	w := httptest.NewRecorder()
	c := callbackContext(t,
		w,
		`{"state":"v23-ip-mismatch","code":"provider-code"}`,
		"9.9.9.9:5555", // mismatched IP
		"TestAgent/1.0",
	)
	h.HandleOAuthCallback(c)

	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	// State row must be deleted on IP mismatch.
	var count int64
	require.NoError(t, db.Model(&model.UserOAuthState{}).Where("state = ?", state.State).Count(&count).Error)
	assert.Equal(t, int64(0), count)
}

func TestOAuthCallback_RejectsStateFromDifferentUserAgent(t *testing.T) {
	db := setupTestDB(t)
	ensureUserOAuthStatesTable(t, db)
	h := setupOAuthTestHandler(t, db)

	state := model.UserOAuthState{
		Provider:     "telegram",
		State:        "v23-ua-mismatch",
		Purpose:      string(model.OAuthPurposeLogin),
		RedirectTo:   "https://app.example.com/auth/callback",
		Nonce:        "expected-nonce",
		CodeVerifier: "expected-verifier",
		ClientIP:     "1.2.3.4",
		UserAgent:    "OriginalAgent/1.0",
		ExpiresAt:    time.Now().UTC().Add(5 * time.Minute),
	}
	require.NoError(t, db.Create(&state).Error)

	w := httptest.NewRecorder()
	c := callbackContext(t,
		w,
		`{"state":"v23-ua-mismatch","code":"provider-code"}`,
		"1.2.3.4:5555",       // matching IP
		"DifferentAgent/2.0", // mismatched UA
	)
	h.HandleOAuthCallback(c)

	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	var count int64
	require.NoError(t, db.Model(&model.UserOAuthState{}).Where("state = ?", state.State).Count(&count).Error)
	assert.Equal(t, int64(0), count)
}

func TestOAuthCallback_StateConsumptionIsAtomic(t *testing.T) {
	db := setupTestDB(t)
	ensureUserOAuthStatesTable(t, db)
	h := setupOAuthTestHandler(t, db)

	// Bind purpose so we can trigger an early "preserve state on
	// unauthorized" case if our atomicity is wrong; but for this test we
	// configure a successful (login) state and have both goroutines try to
	// consume it. The OAuth code exchange will fail because there's no
	// real provider, but the state-consumption side effect (delete) is what
	// we measure: exactly one goroutine should have consumed the row.
	state := model.UserOAuthState{
		Provider:     "telegram",
		State:        "v23-atomic",
		Purpose:      string(model.OAuthPurposeLogin),
		RedirectTo:   "https://app.example.com/auth/callback",
		Nonce:        "expected-nonce",
		CodeVerifier: "expected-verifier",
		ClientIP:     "1.2.3.4",
		UserAgent:    "TestAgent/1.0",
		ExpiresAt:    time.Now().UTC().Add(5 * time.Minute),
	}
	require.NoError(t, db.Create(&state).Error)

	// Probe the consume function directly so we don't need a real OAuth
	// provider — we are testing the state-side semantics, not the full
	// code-exchange path. consumeOAuthState is the V23 atomicity boundary.
	var (
		successes int32
		notFounds int32
		others    int32
		wg        sync.WaitGroup
	)

	const concurrency = 8
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			c := callbackContext(t,
				w,
				`{"state":"v23-atomic","code":"provider-code"}`,
				"1.2.3.4:5555",
				"TestAgent/1.0",
			)
			_, err := h.consumeOAuthState(c, "telegram", "v23-atomic", time.Now().UTC())
			switch {
			case err == nil:
				atomic.AddInt32(&successes, 1)
			case errors.Is(err, errStateNotFound):
				// Either the SELECT FOR UPDATE saw the row gone, or the
				// DELETE's RowsAffected==0 guard fired. Both are correct
				// V23 outcomes for a "lost the race" caller.
				atomic.AddInt32(&notFounds, 1)
			default:
				atomic.AddInt32(&others, 1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), successes, "exactly one goroutine must consume the state")
	assert.Equal(t, int32(concurrency-1), notFounds, "all other goroutines must see the row gone")
	assert.Equal(t, int32(0), others, "no unrelated errors")

	// Row must no longer exist.
	var count int64
	require.NoError(t, db.Model(&model.UserOAuthState{}).Where("state = ?", state.State).Count(&count).Error)
	assert.Equal(t, int64(0), count)
}

// TestInitiateOAuth_PersistsClientIPAndUserAgent verifies that state
// creation populates the V23 binding fields. Without this, the callback
// check would be impossible in the first place.
func TestInitiateOAuth_PersistsClientIPAndUserAgent(t *testing.T) {
	db := setupTestDB(t)
	ensureUserOAuthStatesTable(t, db)
	h := setupOAuthTestHandler(t, db)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/api/v1/me/login-methods/:provider", func(c *gin.Context) {
		middleware.SetUserID(c, 7)
		h.StartBindLoginMethod(c)
	})

	req := httptest.NewRequest(http.MethodPut, "/api/v1/me/login-methods/telegram", bytes.NewBufferString(`{"redirect_to":"https://app.example.com/settings/login-methods"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 V23-Init")
	req.RemoteAddr = "203.0.113.7:54321"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var persisted struct {
		ClientIP  string
		UserAgent string
	}
	require.NoError(t,
		db.Raw("SELECT client_ip, user_agent FROM user_oauth_states WHERE provider = ? ORDER BY id DESC LIMIT 1", "telegram").
			Scan(&persisted).Error,
	)
	assert.Equal(t, "203.0.113.7", persisted.ClientIP)
	assert.Equal(t, "Mozilla/5.0 V23-Init", persisted.UserAgent)
}

// TestOAuthCallback_PreservesStateWhenBindUnauthorized re-asserts the
// historical contract that bind-purpose pre-auth failures must NOT consume
// the state row. The V23 transactional refactor must not regress this.
func TestOAuthCallback_PreservesStateWhenBindUnauthorized(t *testing.T) {
	db := setupTestDB(t)
	ensureUserOAuthStatesTable(t, db)
	h := setupOAuthTestHandler(t, db)

	binder := createTestUser(t, db, "v23-bind-preserve@example.com", "Password123!", true)
	state := model.UserOAuthState{
		Provider:     "telegram",
		State:        "v23-preserve",
		Purpose:      string(model.OAuthPurposeBindLoginMethod),
		UserID:       sql.NullInt64{Int64: int64(binder.ID), Valid: true},
		RedirectTo:   "https://app.example.com/auth/callback",
		Nonce:        "expected-nonce",
		CodeVerifier: "expected-verifier",
		ClientIP:     "1.2.3.4",
		UserAgent:    "TestAgent/1.0",
		ExpiresAt:    time.Now().UTC().Add(5 * time.Minute),
	}
	require.NoError(t, db.Create(&state).Error)

	w := httptest.NewRecorder()
	c := callbackContext(t, w, `{"state":"v23-preserve","code":"provider-code"}`, "1.2.3.4:5555", "TestAgent/1.0")
	h.HandleOAuthCallback(c)

	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	var count int64
	require.NoError(t, db.Model(&model.UserOAuthState{}).Where("state = ?", state.State).Count(&count).Error)
	assert.Equal(t, int64(1), count, "state row must be preserved when bind-callback authorization fails")
}

// recordingLogger captures the rendered SQL emitted by GORM so tests can
// assert that a specific clause (e.g. FOR UPDATE) actually made it into the
// query. We use the public logger.Interface contract so swapping the logger
// onto an existing *gorm.DB requires only a Session(). NB: we do not record
// statements that errored — those are not interesting for clause assertions
// and including them would muddy the matcher.
type recordingLogger struct {
	mu  sync.Mutex
	sql []string
}

func (r *recordingLogger) LogMode(logger.LogLevel) logger.Interface      { return r }
func (r *recordingLogger) Info(context.Context, string, ...interface{})  {}
func (r *recordingLogger) Warn(context.Context, string, ...interface{})  {}
func (r *recordingLogger) Error(context.Context, string, ...interface{}) {}
func (r *recordingLogger) Trace(_ context.Context, _ time.Time, fc func() (string, int64), _ error) {
	sqlStr, _ := fc()
	r.mu.Lock()
	r.sql = append(r.sql, sqlStr)
	r.mu.Unlock()
}
func (r *recordingLogger) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.sql))
	copy(out, r.sql)
	return out
}

// TestConsumeOAuthState_EmitsForUpdateInSelect is a regression guard for
// Critical #1 of the C2 review.
//
// GORM v2 silently ignores the v1 idiom `tx.Set("gorm:query_option", "FOR
// UPDATE")` — the resulting SQL is a plain SELECT with no row lock, which
// breaks the V23 atomicity claim. The fix uses
// `Clauses(clause.Locking{Strength: "UPDATE"})`. This test asserts that
// post-fix the lookup SQL contains "FOR UPDATE"; pre-fix it FAILS, which
// is the empirical proof the v1 idiom was a no-op.
func TestConsumeOAuthState_EmitsForUpdateInSelect(t *testing.T) {
	db := setupTestDB(t)
	ensureUserOAuthStatesTable(t, db)
	h := setupOAuthTestHandler(t, db)

	state := model.UserOAuthState{
		Provider:     "telegram",
		State:        "v23-sql-probe",
		Purpose:      string(model.OAuthPurposeLogin),
		RedirectTo:   "https://app.example.com/auth/callback",
		Nonce:        "expected-nonce",
		CodeVerifier: "expected-verifier",
		ClientIP:     "1.2.3.4",
		UserAgent:    "TestAgent/1.0",
		ExpiresAt:    time.Now().UTC().Add(5 * time.Minute),
	}
	require.NoError(t, db.Create(&state).Error)

	rec := &recordingLogger{}
	// Replace the handler's *gorm.DB with one that uses the recording logger.
	// Session(...) returns a shallow copy with the new logger applied; the
	// underlying connection pool is shared so the row created above is still
	// visible.
	h.db = db.Session(&gorm.Session{Logger: rec})

	w := httptest.NewRecorder()
	c := callbackContext(t, w, `{"state":"v23-sql-probe","code":"x"}`, "1.2.3.4:5555", "TestAgent/1.0")
	_, err := h.consumeOAuthState(c, "telegram", "v23-sql-probe", time.Now().UTC())
	require.NoError(t, err)

	// Find the SELECT against user_oauth_states and assert it is locked.
	var selectSQL string
	for _, s := range rec.snapshot() {
		ls := strings.ToUpper(s)
		if strings.HasPrefix(strings.TrimSpace(ls), "SELECT") && strings.Contains(ls, "USER_OAUTH_STATES") {
			selectSQL = s
			break
		}
	}
	require.NotEmpty(t, selectSQL, "expected a SELECT against user_oauth_states; captured: %v", rec.snapshot())
	assert.Contains(t, strings.ToUpper(selectSQL), "FOR UPDATE",
		"the SELECT lookup MUST carry a row-level lock; without it the V23 atomicity claim is bogus. Captured: %s", selectSQL,
	)
}

package me

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/middleware"
	serviceme "paigram/internal/service/me"
)

type fakeCurrentUserService struct {
	view              *CurrentUserView
	dashboardSummary  *serviceme.DashboardSummaryView
	err               error
	deleteEmailErr    error
	verifyEmailErr    error
	verificationEmail *serviceme.VerificationEmailView
	createdEmail      *serviceme.CreatedEmailView
}

func (f *fakeCurrentUserService) GetCurrentUserView(_ context.Context, _ uint64) (*CurrentUserView, error) {
	return f.view, f.err
}

func (f *fakeCurrentUserService) GetDashboardSummary(_ context.Context, _ uint64) (*serviceme.DashboardSummaryView, error) {
	return f.dashboardSummary, f.err
}

func (f *fakeCurrentUserService) ListEmails(context.Context, uint64) ([]serviceme.EmailView, error) {
	return nil, nil
}

func (f *fakeCurrentUserService) CreateEmail(context.Context, serviceme.CreateEmailInput) (*serviceme.CreatedEmailView, error) {
	return f.createdEmail, nil
}

func (f *fakeCurrentUserService) PatchPrimaryEmail(context.Context, uint64, uint64) error {
	return nil
}

func (f *fakeCurrentUserService) ListLoginMethods(context.Context, uint64) ([]serviceme.LoginMethodView, error) {
	return nil, nil
}

func (f *fakeCurrentUserService) DeleteLoginMethod(context.Context, uint64, string) error {
	return nil
}

func (f *fakeCurrentUserService) DeleteEmail(context.Context, uint64, uint64) error {
	return f.deleteEmailErr
}

func (f *fakeCurrentUserService) VerifyEmail(context.Context, serviceme.VerifyEmailInput) (*serviceme.VerificationEmailView, error) {
	return f.verificationEmail, f.verifyEmailErr
}

type fakeSessionService struct {
	sessions  []SessionView
	revokeErr error
}

func (f *fakeSessionService) ListSessions(_ context.Context, _ uint64, _ string) ([]SessionView, error) {
	return f.sessions, nil
}

func (f *fakeSessionService) RevokeSession(_ context.Context, _ uint64, _ uint64) error {
	return f.revokeErr
}

func testContextWithUser(t *testing.T, method, target string, userID uint64) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(method, target, nil)
	middleware.SetUserID(ctx, userID)
	return ctx, rec
}

func TestCurrentUserHandlerGetMeReturnsCurrentUserView(t *testing.T) {
	handler := NewCurrentUserHandler(&fakeCurrentUserService{view: &CurrentUserView{
		ID:           7,
		DisplayName:  "Planner",
		PrimaryEmail: "user@example.com",
	}})

	ctx, rec := testContextWithUser(t, http.MethodGet, "/api/v1/me", 7)
	handler.GetMe(ctx)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "user@example.com")
}

func TestCurrentUserHandlerGetMeReturnsUnauthorizedWithoutAuthenticatedUser(t *testing.T) {
	handler := NewCurrentUserHandler(&fakeCurrentUserService{})
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)

	handler.GetMe(ctx)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "user not authenticated")
}

func TestCurrentUserHandlerGetDashboardSummaryReturnsSummary(t *testing.T) {
	handler := NewCurrentUserHandler(&fakeCurrentUserService{dashboardSummary: &serviceme.DashboardSummaryView{
		TotalBindings:           3,
		ActiveBindings:          1,
		InvalidBindings:         1,
		RefreshRequiredBindings: 1,
		TotalProfiles:           4,
		EnabledConsumers:        2,
	}})

	ctx, rec := testContextWithUser(t, http.MethodGet, "/api/v1/me/dashboard-summary", 7)
	handler.GetDashboardSummary(ctx)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"total_bindings":3`)
	assert.Contains(t, rec.Body.String(), `"enabled_consumers":2`)
}

func TestSessionHandlerListSessionsUsesMeRoute(t *testing.T) {
	handler := NewSessionHandler(&fakeSessionService{sessions: []SessionView{{ID: 9, IsCurrent: true}}})
	ctx, rec := testContextWithUser(t, http.MethodGet, "/api/v1/me/sessions", 7)

	handler.ListSessions(ctx)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"id":9`)
}

func TestSessionHandlerRevokeSessionReturnsInternalServerErrorWhenServiceFails(t *testing.T) {
	handler := NewSessionHandler(&fakeSessionService{revokeErr: errors.New("revoke failed")})
	ctx, rec := testContextWithUser(t, http.MethodDelete, "/api/v1/me/sessions/99", 7)
	ctx.Params = []gin.Param{{Key: "sessionId", Value: "99"}}

	handler.RevokeSession(ctx)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Contains(t, rec.Body.String(), "revoke failed")
}

func TestCurrentUserHandlerDeleteEmailUsesMeRoute(t *testing.T) {
	handler := NewCurrentUserHandler(&fakeCurrentUserService{})
	ctx, rec := testContextWithUser(t, http.MethodDelete, "/api/v1/me/emails/12", 7)
	ctx.Params = []gin.Param{{Key: "emailId", Value: "12"}}

	handler.DeleteEmail(ctx)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "email deleted successfully")
}

func TestCurrentUserHandlerVerifyEmailUsesMeRoute(t *testing.T) {
	handler := NewCurrentUserHandler(&fakeCurrentUserService{verificationEmail: &serviceme.VerificationEmailView{VerificationExpiresAt: "2026-04-20T00:00:00Z"}})
	ctx, rec := testContextWithUser(t, http.MethodPost, "/api/v1/me/emails/12/verify", 7)
	ctx.Params = []gin.Param{{Key: "emailId", Value: "12"}}

	handler.VerifyEmail(ctx)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "verification email sent successfully")
	assert.Contains(t, rec.Body.String(), "2026-04-20T00:00:00Z")
}

func TestCurrentUserHandlerCreateEmailDoesNotLeakVerificationToken(t *testing.T) {
	handler := NewCurrentUserHandler(&fakeCurrentUserService{createdEmail: &serviceme.CreatedEmailView{
		EmailView: serviceme.EmailView{
			ID:    12,
			Email: "alt@example.com",
		},
		VerificationExpiresAt: time.Date(2026, time.April, 20, 0, 0, 0, 0, time.UTC),
	}})

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	body := bytes.NewBufferString(`{"email":"alt@example.com"}`)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/me/emails", body)
	ctx.Request.Header.Set("Content-Type", "application/json")
	middleware.SetUserID(ctx, 7)

	handler.CreateEmail(ctx)

	require.Equal(t, http.StatusCreated, rec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	data, ok := payload["data"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "alt@example.com", data["email"])
	assert.NotContains(t, data, "verification_token")
	assert.NotEmpty(t, data["verification_expires_at"])
}

func TestCurrentUserHandlerDeleteEmailReturnsNotFoundWhenServiceFails(t *testing.T) {
	handler := NewCurrentUserHandler(&fakeCurrentUserService{deleteEmailErr: serviceme.ErrEmailNotFound})
	ctx, rec := testContextWithUser(t, http.MethodDelete, "/api/v1/me/emails/12", 7)
	ctx.Params = []gin.Param{{Key: "emailId", Value: "12"}}

	handler.DeleteEmail(ctx)

	require.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "email not found")
}

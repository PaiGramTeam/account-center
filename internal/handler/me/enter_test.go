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
	patchPrimaryErr   error
	verificationEmail *serviceme.VerificationEmailView
	createdEmail      *serviceme.CreatedEmailView
	patchedUserID     uint64
	patchedProvider   string
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

func (f *fakeCurrentUserService) SetPrimaryLoginMethod(_ context.Context, userID uint64, provider string) error {
	f.patchedUserID = userID
	f.patchedProvider = provider
	return f.patchPrimaryErr
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
	sessions        []SessionView
	total           int64
	revokeErr       error
	listPage        int
	listPageSize    int
	listAccessToken string
}

func (f *fakeSessionService) ListSessions(_ context.Context, _ uint64, page, pageSize int, accessToken string) ([]SessionView, int64, error) {
	f.listPage = page
	f.listPageSize = pageSize
	f.listAccessToken = accessToken
	return f.sessions, f.total, nil
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
	handler := NewSessionHandler(&fakeSessionService{sessions: []SessionView{{ID: 9, IsCurrent: true}}, total: 1})
	ctx, rec := testContextWithUser(t, http.MethodGet, "/api/v1/me/sessions?page=2&page_size=1", 7)
	ctx.Request.Header.Set("Authorization", "Bearer current-token")

	handler.ListSessions(ctx)

	require.Equal(t, http.StatusOK, rec.Code)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	data, ok := payload["data"].(map[string]any)
	require.True(t, ok)
	items, ok := data["items"].([]any)
	require.True(t, ok)
	require.Len(t, items, 1)
	assert.Equal(t, float64(9), items[0].(map[string]any)["id"])
	pagination, ok := data["pagination"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(1), pagination["total"])
	assert.Equal(t, float64(2), pagination["page"])
	assert.Equal(t, float64(1), pagination["page_size"])
	assert.Equal(t, float64(1), pagination["total_pages"])
	service := handler.service.(*fakeSessionService)
	assert.Equal(t, 2, service.listPage)
	assert.Equal(t, 1, service.listPageSize)
	assert.Equal(t, "current-token", service.listAccessToken)
}

func TestSessionHandlerListSessionsNormalizesInvalidPagination(t *testing.T) {
	fake := &fakeSessionService{sessions: []SessionView{}, total: 0}
	handler := NewSessionHandler(fake)
	ctx, rec := testContextWithUser(t, http.MethodGet, "/api/v1/me/sessions?page=0&page_size=101", 7)

	handler.ListSessions(ctx)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, fake.listPage)
	assert.Equal(t, 20, fake.listPageSize)
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

func TestCurrentUserHandlerPatchPrimaryLoginMethodUsesMeRoute(t *testing.T) {
	service := &fakeCurrentUserService{}
	handler := NewCurrentUserHandler(service)
	ctx, rec := testContextWithUser(t, http.MethodPatch, "/api/v1/me/login-methods/github/primary", 7)
	ctx.Params = []gin.Param{{Key: "provider", Value: "github"}}

	handler.PatchPrimaryLoginMethod(ctx)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, uint64(7), service.patchedUserID)
	assert.Equal(t, "github", service.patchedProvider)
	assert.Contains(t, rec.Body.String(), "primary login method updated successfully")
}

func TestCurrentUserHandlerPatchPrimaryLoginMethodMapsErrors(t *testing.T) {
	tests := []struct {
		name         string
		serviceErr   error
		wantStatus   int
		wantBodyText string
	}{
		{
			name:         "provider not bound",
			serviceErr:   serviceme.ErrProviderNotBound,
			wantStatus:   http.StatusNotFound,
			wantBodyText: "provider not bound to this account",
		},
		{
			name:         "internal error",
			serviceErr:   errors.New("boom"),
			wantStatus:   http.StatusInternalServerError,
			wantBodyText: "failed to set primary login method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewCurrentUserHandler(&fakeCurrentUserService{patchPrimaryErr: tt.serviceErr})
			ctx, rec := testContextWithUser(t, http.MethodPatch, "/api/v1/me/login-methods/github/primary", 7)
			ctx.Params = []gin.Param{{Key: "provider", Value: "github"}}

			handler.PatchPrimaryLoginMethod(ctx)

			require.Equal(t, tt.wantStatus, rec.Code)
			assert.Contains(t, rec.Body.String(), tt.wantBodyText)
		})
	}
}

package user

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/model"
	serviceme "paigram/internal/service/me"
	serviceuser "paigram/internal/service/user"
)

type fakeLoginMethodService struct {
	methods         []serviceme.LoginMethodView
	err             error
	listedUserID    uint64
	patchedUserID   uint64
	patchedProvider string
}

func (f *fakeLoginMethodService) ListLoginMethods(_ context.Context, userID uint64) ([]serviceme.LoginMethodView, error) {
	f.listedUserID = userID
	return f.methods, f.err
}

func (f *fakeLoginMethodService) SetPrimaryLoginMethod(_ context.Context, userID uint64, provider string) error {
	f.patchedUserID = userID
	f.patchedProvider = provider
	return f.err
}

func TestLoginMethodHandlerGetUserLoginMethods(t *testing.T) {
	fake := &fakeLoginMethodService{methods: []serviceme.LoginMethodView{{
		Provider:          "github",
		ProviderAccountID: "github-1",
		DisplayName:       "octocat",
		AvatarURL:         "https://example.com/avatar.png",
		IsPrimary:         true,
		CanUnbind:         false,
		CreatedAt:         time.Date(2026, time.April, 20, 10, 0, 0, 0, time.UTC),
		UpdatedAt:         time.Date(2026, time.April, 20, 11, 0, 0, 0, time.UTC),
	}}}
	handler := &Handler{loginMethods: fake}

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/42/login-methods", nil)
	ctx.Params = []gin.Param{{Key: "id", Value: "42"}}

	handler.ListUserLoginMethods(ctx)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, uint64(42), fake.listedUserID)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	data, ok := payload["data"].([]any)
	require.True(t, ok)
	require.Len(t, data, 1)
	item, ok := data[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "github", item["provider"])
	assert.Equal(t, "github-1", item["provider_account_id"])
	assert.Equal(t, "octocat", item["display_name"])
	assert.Equal(t, "https://example.com/avatar.png", item["avatar_url"])
	assert.Equal(t, true, item["is_primary"])
	assert.Equal(t, false, item["can_unbind"])
	assert.Equal(t, "2026-04-20T10:00:00Z", item["created_at"])
	assert.Equal(t, "2026-04-20T11:00:00Z", item["updated_at"])
}

func TestLoginMethodHandlerPatchUserPrimaryLoginMethodRejectsUnboundProvider(t *testing.T) {
	db := setupTestDB(t)
	serviceGroup := serviceuser.NewServiceGroup(db)
	handler := NewHandlerWithDBAndCache(&serviceGroup.UserService, db, nil)
	handler.loginMethods = serviceme.NewCurrentUserService(db)
	managedUser := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&managedUser).Error)
	require.NoError(t, db.Create(&model.UserCredential{UserID: managedUser.ID, Provider: "email", ProviderAccountID: "user@example.com"}).Error)

	userPath := "/api/v1/admin/users/" + strconv.FormatUint(managedUser.ID, 10) + "/login-methods/github/primary"
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPatch, userPath, nil)
	ctx.Params = []gin.Param{{Key: "id", Value: strconv.FormatUint(managedUser.ID, 10)}, {Key: "provider", Value: "github"}}

	handler.PatchUserPrimaryLoginMethod(ctx)

	require.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "provider not bound to this account")
}

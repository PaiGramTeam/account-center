package user

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/model"
	serviceme "paigram/internal/service/me"
	serviceuser "paigram/internal/service/user"
)

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

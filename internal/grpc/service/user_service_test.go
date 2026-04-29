package service_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcservice "paigram/internal/grpc/service"
	"paigram/internal/model"
	"paigram/internal/testutil"
)

// TestGetUserPermissions_NoMagicAdminBackdoor pins the V17 fix: users with low IDs
// must never be auto-granted admin.all + admin role just because their numeric ID is small.
func TestGetUserPermissions_NoMagicAdminBackdoor(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "user_perm_no_admin_backdoor",
		&model.User{},
		&model.UserEmail{},
		&model.UserProfile{},
	)

	user := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&user).Error)
	require.Less(t, user.ID, uint64(100), "this regression test depends on a low-numeric user id like the legacy backdoor required")

	svc := grpcservice.NewUserService(db)
	resp, err := svc.GetUserPermissions(context.Background(), &grpcservice.GetUserPermissionsRequest{UserId: user.ID})

	if err != nil {
		// Acceptable: the method now refuses to serve until a real role system exists.
		assert.Equal(t, codes.Unimplemented, status.Code(err), "if the method errors it must be Unimplemented, not a leaked admin grant: %v", err)
		assert.Nil(t, resp)
		return
	}

	// Or: a successful response, but it must not contain the legacy magic admin grants.
	require.NotNil(t, resp)
	for _, perm := range resp.Permissions {
		assert.NotEqualf(t, "admin.all", strings.ToLower(perm), "user.ID < 100 must not auto-grant admin.all (got permissions=%v)", resp.Permissions)
	}
	for _, role := range resp.Roles {
		assert.NotEqualf(t, "admin", strings.ToLower(role), "user.ID < 100 must not auto-grant admin role (got roles=%v)", resp.Roles)
	}
}

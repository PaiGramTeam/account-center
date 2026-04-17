package user

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"paigram/internal/model"
	"paigram/internal/testutil"
)

func setupUserRoleServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	return testutil.OpenMySQLTestDB(t, "user_role_service",
		&model.User{},
		&model.Role{},
		&model.UserRole{},
	)
}

func TestUserServiceReplaceUserRolesSetsPrimaryRole(t *testing.T) {
	db := setupUserRoleServiceTestDB(t)
	service := &UserService{db: db}
	user := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	roleA := model.Role{Name: "role-a", DisplayName: "Role A"}
	roleB := model.Role{Name: "role-b", DisplayName: "Role B"}
	require.NoError(t, db.Create(&user).Error)
	require.NoError(t, db.Create(&roleA).Error)
	require.NoError(t, db.Create(&roleB).Error)

	updated, err := service.ReplaceUserRoles(user.ID, []uint64{roleA.ID, roleB.ID}, &roleB.ID, user.ID)
	require.NoError(t, err)
	assert.True(t, updated.PrimaryRoleID.Valid)
	assert.Equal(t, int64(roleB.ID), updated.PrimaryRoleID.Int64)

	var assignments []model.UserRole
	require.NoError(t, db.Where("user_id = ?", user.ID).Order("role_id ASC").Find(&assignments).Error)
	require.Len(t, assignments, 2)
	assert.Equal(t, roleA.ID, assignments[0].RoleID)
	assert.Equal(t, roleB.ID, assignments[1].RoleID)
}

func TestUserServiceReplaceUserRolesRejectsPrimaryRoleOutsideAssignments(t *testing.T) {
	db := setupUserRoleServiceTestDB(t)
	service := &UserService{db: db}
	user := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	roleA := model.Role{Name: "role-a", DisplayName: "Role A"}
	roleB := model.Role{Name: "role-b", DisplayName: "Role B"}
	require.NoError(t, db.Create(&user).Error)
	require.NoError(t, db.Create(&roleA).Error)
	require.NoError(t, db.Create(&roleB).Error)

	_, err := service.ReplaceUserRoles(user.ID, []uint64{roleA.ID}, &roleB.ID, user.ID)
	require.ErrorIs(t, err, ErrPrimaryRoleNotAssigned)
}

func TestUserServiceSetPrimaryRoleRequiresExistingAssignment(t *testing.T) {
	db := setupUserRoleServiceTestDB(t)
	service := &UserService{db: db}
	user := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	role := model.Role{Name: "role-a", DisplayName: "Role A"}
	require.NoError(t, db.Create(&user).Error)
	require.NoError(t, db.Create(&role).Error)

	_, err := service.SetPrimaryRole(user.ID, &role.ID, false)
	require.ErrorIs(t, err, ErrPrimaryRoleNotAssigned)
}

func TestUserServiceSetPrimaryRoleClearsPrimaryRoleWhenRequested(t *testing.T) {
	db := setupUserRoleServiceTestDB(t)
	service := &UserService{db: db}
	user := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	role := model.Role{Name: "role-a", DisplayName: "Role A"}
	require.NoError(t, db.Create(&user).Error)
	require.NoError(t, db.Create(&role).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: user.ID, RoleID: role.ID, GrantedBy: user.ID}).Error)
	require.NoError(t, db.Model(&model.User{}).Where("id = ?", user.ID).Update("primary_role_id", role.ID).Error)

	updated, err := service.SetPrimaryRole(user.ID, nil, true)
	require.NoError(t, err)
	assert.False(t, updated.PrimaryRoleID.Valid)
}

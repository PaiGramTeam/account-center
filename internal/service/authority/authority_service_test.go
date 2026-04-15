package authority

import (
	stderrors "errors"
	"fmt"
	"testing"

	internalcasbin "paigram/internal/casbin"
	"paigram/internal/model"
	servicecasbin "paigram/internal/service/casbin"
	"paigram/internal/testutil"
	pkgerrors "paigram/pkg/errors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type fakeCasbinSyncer struct {
	syncErr   error
	deleteErr error
	synced    []uint
	deleted   []uint
}

func (f *fakeCasbinSyncer) SyncAuthorityPermissionPolicies(roleID uint) error {
	f.synced = append(f.synced, roleID)
	return f.syncErr
}

func (f *fakeCasbinSyncer) DeleteAuthorityPolicies(roleID uint) error {
	f.deleted = append(f.deleted, roleID)
	return f.deleteErr
}

func setupAuthorityServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	return testutil.OpenMySQLTestDB(t, "authority_service",
		&model.Permission{},
		&model.Role{},
		&model.RolePermission{},
		&model.User{},
		&model.UserRole{},
	)
}

func TestGetAuthorityPreloadsPermissions(t *testing.T) {
	db := setupAuthorityServiceTestDB(t)

	perm := model.Permission{Name: "role:read", Resource: "role", Action: "read"}
	require.NoError(t, db.Create(&perm).Error)
	role := model.Role{Name: "detail-role", DisplayName: "Detail Role"}
	require.NoError(t, db.Create(&role).Error)
	require.NoError(t, db.Create(&model.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)

	service := &AuthorityService{db: db}
	loadedRole, err := service.GetAuthority(uint(role.ID))
	require.NoError(t, err)
	require.Len(t, loadedRole.Permissions, 1)
	assert.Equal(t, perm.ID, loadedRole.Permissions[0].ID)
}

func TestCreateAuthorityRollsBackWhenCasbinSyncFails(t *testing.T) {
	db := setupAuthorityServiceTestDB(t)
	perm := model.Permission{Name: "role:read", Resource: "role", Action: "read"}
	require.NoError(t, db.Create(&perm).Error)

	service := &AuthorityService{db: db, casbinService: &fakeCasbinSyncer{syncErr: stderrors.New("sync failed")}}
	role, err := service.CreateAuthority(CreateAuthorityParams{
		Name:          "rollback-create-role",
		Description:   "should roll back",
		PermissionIDs: []uint{uint(perm.ID)},
	})
	require.Error(t, err)
	assert.Nil(t, role)

	var roleCount int64
	require.NoError(t, db.Model(&model.Role{}).Where("name = ?", "rollback-create-role").Count(&roleCount).Error)
	assert.Zero(t, roleCount)

	var rpCount int64
	require.NoError(t, db.Model(&model.RolePermission{}).Count(&rpCount).Error)
	assert.Zero(t, rpCount)
}

func TestAssignPermissionsRestoresPreviousAssignmentsWhenCasbinSyncFails(t *testing.T) {
	db := setupAuthorityServiceTestDB(t)
	oldPerm := model.Permission{Name: "role:read", Resource: "role", Action: "read"}
	newPerm := model.Permission{Name: "role:update", Resource: "role", Action: "update"}
	require.NoError(t, db.Create(&oldPerm).Error)
	require.NoError(t, db.Create(&newPerm).Error)
	role := model.Role{Name: "assign-rollback-role", DisplayName: "Assign Rollback"}
	require.NoError(t, db.Create(&role).Error)
	require.NoError(t, db.Create(&model.RolePermission{RoleID: role.ID, PermissionID: oldPerm.ID}).Error)

	service := &AuthorityService{db: db, casbinService: &fakeCasbinSyncer{syncErr: stderrors.New("sync failed")}}
	err := service.AssignPermissions(uint(role.ID), []uint{uint(newPerm.ID)})
	require.Error(t, err)

	permissions, err := service.GetRolePermissions(uint(role.ID))
	require.NoError(t, err)
	require.Len(t, permissions, 1)
	assert.Equal(t, oldPerm.ID, permissions[0].ID)
}

func TestDeleteAuthorityRemovesCasbinPolicies(t *testing.T) {
	db := setupAuthorityServiceTestDB(t)
	internalcasbin.Reset()
	t.Cleanup(internalcasbin.Reset)

	role := model.Role{Name: "delete-casbin-role", DisplayName: "Delete Casbin Role"}
	require.NoError(t, db.Create(&role).Error)
	_, err := internalcasbin.InitEnforcer(db)
	require.NoError(t, err)

	enforcer := internalcasbin.GetEnforcer()
	_, err = enforcer.AddPolicy(fmt.Sprint(role.ID), "/api/v1/custom/delete-me", "GET")
	require.NoError(t, err)
	require.NoError(t, enforcer.LoadPolicy())

	casbinGroup := servicecasbin.NewServiceGroup(db)
	service := &AuthorityService{db: db, casbinService: &casbinGroup.CasbinService}
	require.NoError(t, service.DeleteAuthority(uint(role.ID)))

	hasPolicy, err := enforcer.Enforce(fmt.Sprint(role.ID), "/api/v1/custom/delete-me", "GET")
	require.NoError(t, err)
	assert.False(t, hasPolicy)

	var deleted model.Role
	assert.Error(t, db.First(&deleted, role.ID).Error)
}

func TestDeleteAuthorityRestoresRoleWhenCasbinDeletionFails(t *testing.T) {
	db := setupAuthorityServiceTestDB(t)
	role := model.Role{Name: "delete-rollback-role", DisplayName: "Delete Rollback Role"}
	require.NoError(t, db.Create(&role).Error)
	perm := model.Permission{Name: "role:delete", Resource: "role", Action: "delete"}
	require.NoError(t, db.Create(&perm).Error)
	require.NoError(t, db.Create(&model.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)

	service := &AuthorityService{db: db, casbinService: &fakeCasbinSyncer{deleteErr: stderrors.New("delete failed")}}
	err := service.DeleteAuthority(uint(role.ID))
	require.Error(t, err)

	var restored model.Role
	require.NoError(t, db.First(&restored, role.ID).Error)

	permissions, err := service.GetRolePermissions(uint(role.ID))
	require.NoError(t, err)
	require.Len(t, permissions, 1)
	assert.Equal(t, perm.ID, permissions[0].ID)
}

func TestGetRolePermissionsReturnsNotFoundForMissingAuthority(t *testing.T) {
	db := setupAuthorityServiceTestDB(t)
	service := &AuthorityService{db: db}

	permissions, err := service.GetRolePermissions(99999)
	require.ErrorIs(t, err, pkgerrors.ErrRoleNotFound)
	assert.Nil(t, permissions)
}

func TestReplaceAuthorityUsersRejectsAdminReplacementWithoutActiveUsers(t *testing.T) {
	db := setupAuthorityServiceTestDB(t)
	service := &AuthorityService{db: db}

	adminRole := model.Role{Name: model.RoleAdmin, DisplayName: "Admin", IsSystem: true}
	require.NoError(t, db.Create(&adminRole).Error)

	activeAdmin := model.User{Status: model.UserStatusActive}
	inactiveAdmin := model.User{Status: model.UserStatusSuspended}
	require.NoError(t, db.Create(&activeAdmin).Error)
	require.NoError(t, db.Create(&inactiveAdmin).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: activeAdmin.ID, RoleID: adminRole.ID, GrantedBy: activeAdmin.ID}).Error)

	err := service.ReplaceAuthorityUsers(uint(adminRole.ID), []uint64{inactiveAdmin.ID}, activeAdmin.ID)
	require.ErrorIs(t, err, pkgerrors.ErrSystemRoleProtect)

	var assignments []model.UserRole
	require.NoError(t, db.Where("role_id = ?", adminRole.ID).Order("user_id ASC").Find(&assignments).Error)
	require.Len(t, assignments, 1)
	assert.Equal(t, activeAdmin.ID, assignments[0].UserID)
}

package permission

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"paigram/internal/model"
)

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Migrate all tables
	err = db.AutoMigrate(
		&model.Permission{},
		&model.Role{},
		&model.RolePermission{},
		&model.User{},
		&model.UserRole{},
	)
	require.NoError(t, err)

	return db
}

func createTestUser(t *testing.T, db *gorm.DB) *model.User {
	user := &model.User{
		PrimaryLoginType: model.LoginTypeEmail,
		Status:           model.UserStatusActive,
	}
	err := db.Create(user).Error
	require.NoError(t, err)
	return user
}

func TestManager_CreatePermission(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	perm, err := mgr.CreatePermission("test:create", "test", "create", "Test create permission")
	require.NoError(t, err)
	assert.NotZero(t, perm.ID)
	assert.Equal(t, "test:create", perm.Name)
	assert.Equal(t, "test", perm.Resource)
	assert.Equal(t, "create", perm.Action)
}

func TestManager_GetPermissionByName(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	// Create permission
	created, err := mgr.CreatePermission("test:read", "test", "read", "Test read permission")
	require.NoError(t, err)

	// Get by name
	found, err := mgr.GetPermissionByName("test:read")
	require.NoError(t, err)
	assert.Equal(t, created.ID, found.ID)
	assert.Equal(t, "test:read", found.Name)

	// Not found
	_, err = mgr.GetPermissionByName("nonexistent")
	assert.ErrorIs(t, err, ErrPermissionNotFound)
}

func TestManager_CreateRole(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	role, err := mgr.CreateRole("admin", "Administrator", "Full access", true)
	require.NoError(t, err)
	assert.NotZero(t, role.ID)
	assert.Equal(t, "admin", role.Name)
	assert.Equal(t, "Administrator", role.DisplayName)
	assert.True(t, role.IsSystem)
}

func TestManager_GetRoleByName(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	created, err := mgr.CreateRole("moderator", "Moderator", "Limited admin", false)
	require.NoError(t, err)

	found, err := mgr.GetRoleByName("moderator")
	require.NoError(t, err)
	assert.Equal(t, created.ID, found.ID)
	assert.Equal(t, "moderator", found.Name)

	_, err = mgr.GetRoleByName("nonexistent")
	assert.ErrorIs(t, err, ErrRoleNotFound)
}

func TestManager_DeleteRole(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	// Create non-system role
	role, err := mgr.CreateRole("custom", "Custom Role", "Test", false)
	require.NoError(t, err)

	// Delete should succeed
	err = mgr.DeleteRole(role.ID)
	assert.NoError(t, err)

	// Should not be found
	_, err = mgr.GetRoleByID(role.ID)
	assert.Error(t, err)
}

func TestManager_DeleteRole_SystemRole(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	// Create system role
	role, err := mgr.CreateRole("admin", "Admin", "System role", true)
	require.NoError(t, err)

	// Delete should fail
	err = mgr.DeleteRole(role.ID)
	assert.ErrorIs(t, err, ErrCannotDeleteSystemRole)
}

func TestManager_AssignPermissionToRole(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	// Create permission and role
	perm, err := mgr.CreatePermission("test:read", "test", "read", "Test")
	require.NoError(t, err)

	role, err := mgr.CreateRole("tester", "Tester", "Test role", false)
	require.NoError(t, err)

	// Assign permission
	err = mgr.AssignPermissionToRole(role.ID, perm.ID)
	assert.NoError(t, err)

	// Verify assignment
	foundRole, err := mgr.GetRoleByID(role.ID)
	require.NoError(t, err)
	assert.Len(t, foundRole.Permissions, 1)
	assert.Equal(t, perm.ID, foundRole.Permissions[0].ID)
}

func TestManager_RemovePermissionFromRole(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	// Create and assign permission
	perm, err := mgr.CreatePermission("test:write", "test", "write", "Test")
	require.NoError(t, err)

	role, err := mgr.CreateRole("writer", "Writer", "Write role", false)
	require.NoError(t, err)

	err = mgr.AssignPermissionToRole(role.ID, perm.ID)
	require.NoError(t, err)

	// Remove permission
	err = mgr.RemovePermissionFromRole(role.ID, perm.ID)
	assert.NoError(t, err)

	// Verify removal
	foundRole, err := mgr.GetRoleByID(role.ID)
	require.NoError(t, err)
	assert.Len(t, foundRole.Permissions, 0)
}

func TestManager_AssignRoleToUser(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	user := createTestUser(t, db)
	role, err := mgr.CreateRole("user", "User", "Regular user", false)
	require.NoError(t, err)

	// Assign role
	err = mgr.AssignRoleToUser(user.ID, role.ID, user.ID)
	assert.NoError(t, err)

	// Verify assignment
	roles, err := mgr.GetUserRoles(user.ID)
	require.NoError(t, err)
	assert.Len(t, roles, 1)
	assert.Equal(t, role.ID, roles[0].ID)
}

func TestManager_AssignRoleToUser_Duplicate(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	user := createTestUser(t, db)
	role, err := mgr.CreateRole("user", "User", "Regular user", false)
	require.NoError(t, err)

	// First assignment
	err = mgr.AssignRoleToUser(user.ID, role.ID, user.ID)
	require.NoError(t, err)

	// Duplicate assignment should fail
	err = mgr.AssignRoleToUser(user.ID, role.ID, user.ID)
	assert.ErrorIs(t, err, ErrUserAlreadyHasRole)
}

func TestManager_RemoveRoleFromUser(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	user := createTestUser(t, db)
	role, err := mgr.CreateRole("user", "User", "Regular user", false)
	require.NoError(t, err)

	err = mgr.AssignRoleToUser(user.ID, role.ID, user.ID)
	require.NoError(t, err)

	// Remove role
	err = mgr.RemoveRoleFromUser(user.ID, role.ID)
	assert.NoError(t, err)

	// Verify removal
	roles, err := mgr.GetUserRoles(user.ID)
	require.NoError(t, err)
	assert.Len(t, roles, 0)
}

func TestManager_HasPermission(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	// Setup: user -> role -> permission
	user := createTestUser(t, db)
	perm, err := mgr.CreatePermission("test:execute", "test", "execute", "Test")
	require.NoError(t, err)

	role, err := mgr.CreateRole("executor", "Executor", "Can execute", false)
	require.NoError(t, err)

	err = mgr.AssignPermissionToRole(role.ID, perm.ID)
	require.NoError(t, err)

	err = mgr.AssignRoleToUser(user.ID, role.ID, user.ID)
	require.NoError(t, err)

	// Test permission check
	has, err := mgr.HasPermission(user.ID, "test:execute")
	require.NoError(t, err)
	assert.True(t, has)

	// Test non-existent permission
	has, err = mgr.HasPermission(user.ID, "test:nonexistent")
	require.NoError(t, err)
	assert.False(t, has)
}

func TestManager_HasRole(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	user := createTestUser(t, db)
	role, err := mgr.CreateRole("admin", "Admin", "Administrator", true)
	require.NoError(t, err)

	err = mgr.AssignRoleToUser(user.ID, role.ID, user.ID)
	require.NoError(t, err)

	// Has role
	has, err := mgr.HasRole(user.ID, "admin")
	require.NoError(t, err)
	assert.True(t, has)

	// Does not have role
	has, err = mgr.HasRole(user.ID, "moderator")
	require.NoError(t, err)
	assert.False(t, has)
}

func TestManager_HasAnyRole(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	user := createTestUser(t, db)
	moderatorRole, err := mgr.CreateRole("moderator", "Moderator", "Mod", false)
	require.NoError(t, err)

	err = mgr.AssignRoleToUser(user.ID, moderatorRole.ID, user.ID)
	require.NoError(t, err)

	// Has one of the roles
	has, err := mgr.HasAnyRole(user.ID, []string{"admin", "moderator"})
	require.NoError(t, err)
	assert.True(t, has)

	// Does not have any of the roles
	has, err = mgr.HasAnyRole(user.ID, []string{"admin", "guest"})
	require.NoError(t, err)
	assert.False(t, has)
}

func TestManager_HasAllRoles(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	user := createTestUser(t, db)
	role1, err := mgr.CreateRole("role1", "Role 1", "First role", false)
	require.NoError(t, err)
	role2, err := mgr.CreateRole("role2", "Role 2", "Second role", false)
	require.NoError(t, err)

	err = mgr.AssignRoleToUser(user.ID, role1.ID, user.ID)
	require.NoError(t, err)
	err = mgr.AssignRoleToUser(user.ID, role2.ID, user.ID)
	require.NoError(t, err)

	// Has all roles
	has, err := mgr.HasAllRoles(user.ID, []string{"role1", "role2"})
	require.NoError(t, err)
	assert.True(t, has)

	// Does not have all roles
	has, err = mgr.HasAllRoles(user.ID, []string{"role1", "role2", "role3"})
	require.NoError(t, err)
	assert.False(t, has)
}

func TestManager_RequirePermission(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	user := createTestUser(t, db)
	perm, err := mgr.CreatePermission("test:action", "test", "action", "Test")
	require.NoError(t, err)

	role, err := mgr.CreateRole("actor", "Actor", "Can act", false)
	require.NoError(t, err)

	err = mgr.AssignPermissionToRole(role.ID, perm.ID)
	require.NoError(t, err)

	err = mgr.AssignRoleToUser(user.ID, role.ID, user.ID)
	require.NoError(t, err)

	// Should succeed
	err = mgr.RequirePermission(user.ID, "test:action")
	assert.NoError(t, err)

	// Should fail
	err = mgr.RequirePermission(user.ID, "test:denied")
	assert.ErrorIs(t, err, ErrPermissionDenied)
}

func TestManager_RequireRole(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	user := createTestUser(t, db)
	role, err := mgr.CreateRole("admin", "Admin", "Administrator", true)
	require.NoError(t, err)

	err = mgr.AssignRoleToUser(user.ID, role.ID, user.ID)
	require.NoError(t, err)

	// Should succeed
	err = mgr.RequireRole(user.ID, "admin")
	assert.NoError(t, err)

	// Should fail
	err = mgr.RequireRole(user.ID, "moderator")
	assert.ErrorIs(t, err, ErrPermissionDenied)
}

func TestManager_GetUserPermissions(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	user := createTestUser(t, db)

	// Create permissions
	perm1, err := mgr.CreatePermission("test:read", "test", "read", "Read")
	require.NoError(t, err)
	perm2, err := mgr.CreatePermission("test:write", "test", "write", "Write")
	require.NoError(t, err)

	// Create role with permissions
	role, err := mgr.CreateRole("editor", "Editor", "Can edit", false)
	require.NoError(t, err)

	err = mgr.AssignPermissionToRole(role.ID, perm1.ID)
	require.NoError(t, err)
	err = mgr.AssignPermissionToRole(role.ID, perm2.ID)
	require.NoError(t, err)

	// Assign role to user
	err = mgr.AssignRoleToUser(user.ID, role.ID, user.ID)
	require.NoError(t, err)

	// Get user permissions
	perms, err := mgr.GetUserPermissions(user.ID)
	require.NoError(t, err)
	assert.Len(t, perms, 2)
}

func TestManager_GetUserPermissions_MultipleRoles(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	user := createTestUser(t, db)

	// Create permissions
	perm1, err := mgr.CreatePermission("user:read", "user", "read", "Read users")
	require.NoError(t, err)
	perm2, err := mgr.CreatePermission("bot:read", "bot", "read", "Read bots")
	require.NoError(t, err)
	perm3, err := mgr.CreatePermission("bot:create", "bot", "create", "Create bots")
	require.NoError(t, err)

	// Create two roles
	role1, err := mgr.CreateRole("viewer", "Viewer", "Can view", false)
	require.NoError(t, err)
	role2, err := mgr.CreateRole("creator", "Creator", "Can create", false)
	require.NoError(t, err)

	// Assign permissions to roles
	err = mgr.AssignPermissionToRole(role1.ID, perm1.ID)
	require.NoError(t, err)
	err = mgr.AssignPermissionToRole(role1.ID, perm2.ID)
	require.NoError(t, err)
	err = mgr.AssignPermissionToRole(role2.ID, perm3.ID)
	require.NoError(t, err)

	// Assign both roles to user
	err = mgr.AssignRoleToUser(user.ID, role1.ID, user.ID)
	require.NoError(t, err)
	err = mgr.AssignRoleToUser(user.ID, role2.ID, user.ID)
	require.NoError(t, err)

	// Get user permissions (should get all 3 permissions)
	perms, err := mgr.GetUserPermissions(user.ID)
	require.NoError(t, err)
	assert.Len(t, perms, 3)

	// Verify each permission
	has, err := mgr.HasPermission(user.ID, "user:read")
	require.NoError(t, err)
	assert.True(t, has)

	has, err = mgr.HasPermission(user.ID, "bot:read")
	require.NoError(t, err)
	assert.True(t, has)

	has, err = mgr.HasPermission(user.ID, "bot:create")
	require.NoError(t, err)
	assert.True(t, has)
}

func TestManager_UpdateRole(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	role, err := mgr.CreateRole("editor", "Editor", "Original description", false)
	require.NoError(t, err)

	// Update role
	updated, err := mgr.UpdateRole(role.ID, "Senior Editor", "Updated description")
	require.NoError(t, err)
	assert.Equal(t, "Senior Editor", updated.DisplayName)
	assert.Equal(t, "Updated description", updated.Description)
	assert.Equal(t, "editor", updated.Name) // Name should not change
}

func TestManager_ListPermissions(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	// Create multiple permissions
	_, err := mgr.CreatePermission("user:create", "user", "create", "Create users")
	require.NoError(t, err)
	_, err = mgr.CreatePermission("user:read", "user", "read", "Read users")
	require.NoError(t, err)

	perms, err := mgr.ListPermissions()
	require.NoError(t, err)
	assert.Len(t, perms, 2)
}

func TestManager_ListRoles(t *testing.T) {
	db := setupTestDB(t)
	mgr := NewManager(db)

	// Create multiple roles
	_, err := mgr.CreateRole("admin", "Admin", "Administrator", true)
	require.NoError(t, err)
	_, err = mgr.CreateRole("user", "User", "Regular user", false)
	require.NoError(t, err)

	roles, err := mgr.ListRoles()
	require.NoError(t, err)
	assert.Len(t, roles, 2)
}

func TestBuildPermissionName(t *testing.T) {
	tests := []struct {
		resource string
		action   string
		expected string
	}{
		{"user", "create", "user:create"},
		{"bot", "delete", "bot:delete"},
		{"role", "manage", "role:manage"},
	}

	for _, tt := range tests {
		result := model.BuildPermissionName(tt.resource, tt.action)
		assert.Equal(t, tt.expected, result)
	}
}

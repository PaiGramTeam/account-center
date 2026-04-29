package seed

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"paigram/internal/casbin"
	"paigram/internal/model"
	"paigram/internal/testutil"
)

func setupTestDB(t *testing.T) *gorm.DB {
	db := testutil.OpenMySQLTestDB(t, "seed",
		&model.Permission{},
		&model.Role{},
		&model.RolePermission{},
		&model.User{},
		&model.UserRole{},
		&model.UserProfile{},
		&model.UserEmail{},
		&model.UserCredential{},
	)

	return db
}

func TestSeedPermissions(t *testing.T) {
	db := setupTestDB(t)

	err := SeedPermissions(db)
	require.NoError(t, err)

	// Verify permissions were created
	var count int64
	err = db.Model(&model.Permission{}).Count(&count).Error
	require.NoError(t, err)
	assert.Equal(t, int64(len(DefaultPermissions)), count)

	// Verify specific permission
	var perm model.Permission
	err = db.Where("name = ?", "user:create").First(&perm).Error
	require.NoError(t, err)
	assert.Equal(t, "user", perm.Resource)
	assert.Equal(t, "create", perm.Action)
}

func TestSeedPermissions_Idempotent(t *testing.T) {
	db := setupTestDB(t)

	// Run twice
	err := SeedPermissions(db)
	require.NoError(t, err)

	err = SeedPermissions(db)
	require.NoError(t, err)

	// Should still have same count
	var count int64
	err = db.Model(&model.Permission{}).Count(&count).Error
	require.NoError(t, err)
	assert.Equal(t, int64(len(DefaultPermissions)), count)
}

func TestSeedRoles(t *testing.T) {
	db := setupTestDB(t)

	// Seed permissions first
	err := SeedPermissions(db)
	require.NoError(t, err)

	// Seed roles
	err = SeedRoles(db)
	require.NoError(t, err)

	// Verify roles were created
	var count int64
	err = db.Model(&model.Role{}).Count(&count).Error
	require.NoError(t, err)
	assert.Equal(t, int64(len(DefaultRoles)), count)

	// Verify admin role has permissions
	var adminRole model.Role
	err = db.Preload("Permissions").Where("name = ?", "admin").First(&adminRole).Error
	require.NoError(t, err)
	assert.True(t, adminRole.IsSystem)
	assert.Greater(t, len(adminRole.Permissions), 0)
	assert.Contains(t, permissionNames(adminRole.Permissions), model.BuildPermissionName(model.ResourcePlatformAccount, model.ActionRead))
	assert.Contains(t, permissionNames(adminRole.Permissions), model.BuildPermissionName(model.ResourcePlatformAccount, model.ActionList))
	assert.Contains(t, permissionNames(adminRole.Permissions), model.BuildPermissionName(model.ResourcePlatformAccount, model.ActionUpdate))
	assert.Contains(t, permissionNames(adminRole.Permissions), model.BuildPermissionName(model.ResourcePlatformAccount, model.ActionDelete))
}

func TestSeedPermissions_IncludesPlatformAccountPermissions(t *testing.T) {
	db := setupTestDB(t)

	err := SeedPermissions(db)
	require.NoError(t, err)

	for _, permissionName := range []string{
		model.BuildPermissionName(model.ResourcePlatformAccount, model.ActionRead),
		model.BuildPermissionName(model.ResourcePlatformAccount, model.ActionList),
		model.BuildPermissionName(model.ResourcePlatformAccount, model.ActionUpdate),
		model.BuildPermissionName(model.ResourcePlatformAccount, model.ActionDelete),
	} {
		var perm model.Permission
		err = db.Where("name = ?", permissionName).First(&perm).Error
		require.NoError(t, err)
		assert.Equal(t, model.ResourcePlatformAccount, perm.Resource)
	}
}

func TestSeedRoles_UpdatePermissions(t *testing.T) {
	db := setupTestDB(t)

	// Initial seed
	err := SeedPermissions(db)
	require.NoError(t, err)
	err = SeedRoles(db)
	require.NoError(t, err)

	// Get admin role
	var adminRole model.Role
	err = db.Preload("Permissions").Where("name = ?", "admin").First(&adminRole).Error
	require.NoError(t, err)
	initialPermCount := len(adminRole.Permissions)

	// Run seed again (should update permissions if DefaultRoles changed)
	err = SeedRoles(db)
	require.NoError(t, err)

	// Verify permissions are still correct
	err = db.Preload("Permissions").Where("name = ?", "admin").First(&adminRole).Error
	require.NoError(t, err)
	assert.Equal(t, initialPermCount, len(adminRole.Permissions))
}

func TestSeedRoles_ClearsStalePermissionsForEmptyRole(t *testing.T) {
	db := setupTestDB(t)

	require.NoError(t, SeedPermissions(db))
	require.NoError(t, SeedRoles(db))

	var guestRole model.Role
	err := db.Where("name = ?", model.RoleGuest).First(&guestRole).Error
	require.NoError(t, err)

	var userReadPermission model.Permission
	err = db.Where("name = ?", model.BuildPermissionName(model.ResourceUser, model.ActionRead)).First(&userReadPermission).Error
	require.NoError(t, err)

	staleAssignment := model.RolePermission{RoleID: guestRole.ID, PermissionID: userReadPermission.ID}
	require.NoError(t, db.Create(&staleAssignment).Error)

	require.NoError(t, SeedRoles(db))

	var count int64
	err = db.Model(&model.RolePermission{}).Where("role_id = ?", guestRole.ID).Count(&count).Error
	require.NoError(t, err)
	assert.Zero(t, count)
}

func TestRun(t *testing.T) {
	db := setupTestDB(t)

	// Initialize Casbin enforcer before seeding
	_, err := casbin.InitEnforcer(db)
	require.NoError(t, err)

	err = Run(db)
	require.NoError(t, err)

	// Verify permissions exist
	var permCount int64
	err = db.Model(&model.Permission{}).Count(&permCount).Error
	require.NoError(t, err)
	assert.Greater(t, permCount, int64(0))

	// Verify roles exist
	var roleCount int64
	err = db.Model(&model.Role{}).Count(&roleCount).Error
	require.NoError(t, err)
	assert.Greater(t, roleCount, int64(0))
}

func permissionNames(perms []model.Permission) []string {
	names := make([]string, 0, len(perms))
	for _, perm := range perms {
		names = append(names, perm.Name)
	}
	return names
}

func TestSeedCasbinPoliciesAddsMissingRulesWhenPoliciesAlreadyExist(t *testing.T) {
	db := setupTestDB(t)
	casbin.Reset()
	t.Cleanup(casbin.Reset)

	require.NoError(t, SeedPermissions(db))
	require.NoError(t, SeedRoles(db))
	_, err := casbin.InitEnforcer(db)
	require.NoError(t, err)

	var adminRole model.Role
	err = db.Where("name = ?", model.RoleAdmin).First(&adminRole).Error
	require.NoError(t, err)
	adminID := strconv.FormatUint(adminRole.ID, 10)

	enforcer := casbin.GetEnforcer()
	_, err = enforcer.AddPolicy(adminID, "/api/v1/users", "GET")
	require.NoError(t, err)

	err = SeedCasbinPolicies(db)
	require.NoError(t, err)

	hasPolicy, err := enforcer.Enforce(adminID, "/api/v1/admin/roles/1/permissions", "PUT")
	require.NoError(t, err)
	assert.True(t, hasPolicy)

	hasPolicy, err = enforcer.Enforce(adminID, "/api/v1/admin/roles/1/users", "GET")
	require.NoError(t, err)
	assert.True(t, hasPolicy)
}

func TestSeedCasbinPoliciesInitializesEnforcerWhenNeeded(t *testing.T) {
	db := setupTestDB(t)
	casbin.Reset()
	t.Cleanup(casbin.Reset)

	require.NoError(t, SeedPermissions(db))
	require.NoError(t, SeedRoles(db))

	require.NotPanics(t, func() {
		err := SeedCasbinPolicies(db)
		require.NoError(t, err)
	})

	enforcer := casbin.GetEnforcer()
	require.NotNil(t, enforcer)

	var adminRole model.Role
	err := db.Where("name = ?", model.RoleAdmin).First(&adminRole).Error
	require.NoError(t, err)

	hasPolicy, err := enforcer.Enforce(strconv.FormatUint(adminRole.ID, 10), "/api/v1/admin/roles/1/permissions", "PUT")
	require.NoError(t, err)
	assert.True(t, hasPolicy)
}

func TestSeedCasbinPoliciesRemovesObsoleteBuiltInRolePoliciesOnly(t *testing.T) {
	db := setupTestDB(t)
	casbin.Reset()
	t.Cleanup(casbin.Reset)

	require.NoError(t, SeedPermissions(db))
	require.NoError(t, SeedRoles(db))
	_, err := casbin.InitEnforcer(db)
	require.NoError(t, err)

	customRole := model.Role{Name: "custom-task1-role", DisplayName: "Custom", Description: "custom test role"}
	require.NoError(t, db.Create(&customRole).Error)

	var adminRole model.Role
	err = db.Where("name = ?", model.RoleAdmin).First(&adminRole).Error
	require.NoError(t, err)

	enforcer := casbin.GetEnforcer()
	adminID := strconv.FormatUint(adminRole.ID, 10)
	customID := strconv.FormatUint(customRole.ID, 10)

	_, err = enforcer.AddPolicy(adminID, "/api/v1/menu", "GET")
	require.NoError(t, err)
	_, err = enforcer.AddPolicy(customID, "/api/v1/menu", "GET")
	require.NoError(t, err)

	err = SeedCasbinPolicies(db)
	require.NoError(t, err)

	hasObsoleteAdminPolicy, err := enforcer.Enforce(adminID, "/api/v1/menu", "GET")
	require.NoError(t, err)
	assert.False(t, hasObsoleteAdminPolicy)

	hasCustomPolicy, err := enforcer.Enforce(customID, "/api/v1/menu", "GET")
	require.NoError(t, err)
	assert.True(t, hasCustomPolicy)
}

func TestSeedCasbinPoliciesMatchesDefaultRolePermissionCatalog(t *testing.T) {
	db := setupTestDB(t)
	casbin.Reset()
	t.Cleanup(casbin.Reset)

	require.NoError(t, SeedPermissions(db))
	require.NoError(t, SeedRoles(db))
	require.NoError(t, SeedCasbinPolicies(db))

	enforcer := casbin.GetEnforcer()
	for _, roleDef := range DefaultRoles {
		var role model.Role
		err := db.Where("name = ?", roleDef.Name).First(&role).Error
		require.NoError(t, err)

		actual := normalizePolicySet(enforcer.GetFilteredPolicy(0, strconv.FormatUint(role.ID, 10)))
		expected := normalizePolicySet(buildSeedPolicies(strconv.FormatUint(role.ID, 10), casbin.PoliciesForSystemRole(roleDef.Name)))
		assert.Equal(t, expected, actual, roleDef.Name)
	}
}

func TestVerifySeedCasbinPoliciesDetectsMissingManagedPolicy(t *testing.T) {
	db := setupTestDB(t)
	casbin.Reset()
	t.Cleanup(casbin.Reset)

	require.NoError(t, SeedPermissions(db))
	require.NoError(t, SeedRoles(db))
	require.NoError(t, SeedCasbinPolicies(db))

	var adminRole model.Role
	require.NoError(t, db.Where("name = ?", model.RoleAdmin).First(&adminRole).Error)

	enforcer := casbin.GetEnforcer()
	removed, err := enforcer.RemovePolicy(strconv.FormatUint(adminRole.ID, 10), "/api/v1/admin/roles/:id/permissions", "PUT")
	require.NoError(t, err)
	require.True(t, removed)
	require.NoError(t, enforcer.LoadPolicy())

	drift, err := VerifySeedCasbinPolicies(db)
	require.NoError(t, err)
	require.Len(t, drift, 1)
	assert.Equal(t, model.RoleAdmin, drift[0].RoleName)
	assert.Contains(t, normalizePolicySet(drift[0].Missing), strings.Join([]string{strconv.FormatUint(adminRole.ID, 10), "/api/v1/admin/roles/:id/permissions", "PUT"}, "|"))
	assert.Empty(t, drift[0].Unexpected)
}

func normalizePolicySet(policies [][]string) []string {
	normalized := make([]string, 0, len(policies))
	for _, policy := range policies {
		normalized = append(normalized, strings.Join(policy, "|"))
	}
	slices.Sort(normalized)
	return normalized
}

func TestCreateDefaultAdmin(t *testing.T) {
	db := setupTestDB(t)

	// Seed roles first
	err := SeedPermissions(db)
	require.NoError(t, err)
	err = SeedRoles(db)
	require.NoError(t, err)

	// Set test environment variables
	t.Setenv("ADMIN_EMAIL", "test-admin@example.com")
	t.Setenv("ADMIN_PASSWORD", "TestPassword123!")
	t.Setenv("ADMIN_NAME", "Test Admin")

	err = CreateDefaultAdmin(db, 12)
	require.NoError(t, err)

	// Verify user was created
	var user model.User
	err = db.First(&user).Error
	require.NoError(t, err)
	assert.Equal(t, model.UserStatusActive, user.Status)

	// Verify profile
	var profile model.UserProfile
	err = db.Where("user_id = ?", user.ID).First(&profile).Error
	require.NoError(t, err)
	assert.Equal(t, "Test Admin", profile.DisplayName)

	// Verify email
	var email model.UserEmail
	err = db.Where("user_id = ?", user.ID).First(&email).Error
	require.NoError(t, err)
	assert.Equal(t, "test-admin@example.com", email.Email)
	assert.True(t, email.IsPrimary)
	assert.True(t, email.VerifiedAt.Valid)

	// Verify credential
	var credential model.UserCredential
	err = db.Where("user_id = ? AND provider = ?", user.ID, "email").First(&credential).Error
	require.NoError(t, err)
	assert.NotEmpty(t, credential.PasswordHash)

	// Verify admin role assignment
	var userRole model.UserRole
	err = db.Where("user_id = ?", user.ID).First(&userRole).Error
	require.NoError(t, err)

	var adminRole model.Role
	err = db.Where("name = ?", "admin").First(&adminRole).Error
	require.NoError(t, err)
	assert.Equal(t, adminRole.ID, userRole.RoleID)
}

func TestCreateDefaultAdmin_Idempotent(t *testing.T) {
	db := setupTestDB(t)

	// Seed roles
	err := SeedPermissions(db)
	require.NoError(t, err)
	err = SeedRoles(db)
	require.NoError(t, err)

	t.Setenv("ADMIN_EMAIL", "idempotent-admin@example.com")
	t.Setenv("ADMIN_PASSWORD", "IdempotentPass123!")
	t.Setenv("ADMIN_NAME", "Idempotent Admin")

	// Create admin first time
	err = CreateDefaultAdmin(db, 12)
	require.NoError(t, err)

	var count int64
	err = db.Model(&model.User{}).Count(&count).Error
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Create admin second time (should skip)
	err = CreateDefaultAdmin(db, 12)
	require.NoError(t, err)

	// Should still have only one user
	err = db.Model(&model.User{}).Count(&count).Error
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestCreateDefaultAdmin_WithoutAdminRole(t *testing.T) {
	db := setupTestDB(t)

	// Don't seed roles
	err := CreateDefaultAdmin(db, 12)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "admin role not found")
}

func TestSeed_FailsClosedWhenAdminPasswordEmpty(t *testing.T) {
	// V6: ADMIN_PASSWORD is now mandatory. Auto-generating a password
	// would either leak via stdout/stderr (caught by log aggregators) or
	// require fragile TTY-only printing. The cleanest fix is to refuse
	// to seed at all unless the operator supplies a password.
	db := setupTestDB(t)

	require.NoError(t, SeedPermissions(db))
	require.NoError(t, SeedRoles(db))

	t.Setenv("ADMIN_EMAIL", "")
	t.Setenv("ADMIN_PASSWORD", "")
	t.Setenv("ADMIN_NAME", "")

	err := CreateDefaultAdmin(db, 12)
	require.Error(t, err, "must refuse to seed when ADMIN_PASSWORD is unset")
	require.Contains(t, err.Error(), "ADMIN_PASSWORD")

	// No user, profile, email, credential, or role assignment must have
	// been created.
	var userCount int64
	require.NoError(t, db.Model(&model.User{}).Count(&userCount).Error)
	assert.Equal(t, int64(0), userCount, "no user must be created on fail-closed path")

	var credentialCount int64
	require.NoError(t, db.Model(&model.UserCredential{}).Count(&credentialCount).Error)
	assert.Equal(t, int64(0), credentialCount, "no credential must be created on fail-closed path")
}

func TestCreateDefaultAdmin_RequiresExplicitPasswordEvenWhenEmailProvided(t *testing.T) {
	// V6 corollary: setting only ADMIN_EMAIL still does not allow
	// auto-generation; ADMIN_PASSWORD remains mandatory.
	db := setupTestDB(t)

	require.NoError(t, SeedPermissions(db))
	require.NoError(t, SeedRoles(db))

	t.Setenv("ADMIN_EMAIL", "ops@example.com")
	t.Setenv("ADMIN_PASSWORD", "")

	err := CreateDefaultAdmin(db, 12)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ADMIN_PASSWORD")
}

func TestCreateDefaultAdmin_CreatesReplacementWhenExistingAdminAssignmentIsInactive(t *testing.T) {
	db := setupTestDB(t)

	require.NoError(t, SeedPermissions(db))
	require.NoError(t, SeedRoles(db))

	var adminRole model.Role
	require.NoError(t, db.Where("name = ?", model.RoleAdmin).First(&adminRole).Error)

	inactiveUser := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusSuspended}
	require.NoError(t, db.Create(&inactiveUser).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: inactiveUser.ID, RoleID: adminRole.ID, GrantedBy: inactiveUser.ID}).Error)

	t.Setenv("ADMIN_EMAIL", "replacement-admin@example.com")
	t.Setenv("ADMIN_PASSWORD", "ReplacementPass123!")
	t.Setenv("ADMIN_NAME", "Replacement Admin")

	require.NoError(t, CreateDefaultAdmin(db, 12))

	var activeAdminCount int64
	require.NoError(t, db.Table("user_roles").
		Joins("JOIN users ON users.id = user_roles.user_id").
		Where("user_roles.role_id = ? AND users.status = ?", adminRole.ID, model.UserStatusActive).
		Count(&activeAdminCount).Error)
	assert.Equal(t, int64(1), activeAdminCount)

	var totalUsers int64
	require.NoError(t, db.Model(&model.User{}).Count(&totalUsers).Error)
	assert.Equal(t, int64(2), totalUsers)
}

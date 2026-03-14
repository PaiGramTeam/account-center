package seed

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

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

func TestRun(t *testing.T) {
	db := setupTestDB(t)

	err := Run(db)
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

	err = CreateDefaultAdmin(db)
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

	// Create admin first time
	err = CreateDefaultAdmin(db)
	require.NoError(t, err)

	var count int64
	err = db.Model(&model.User{}).Count(&count).Error
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Create admin second time (should skip)
	err = CreateDefaultAdmin(db)
	require.NoError(t, err)

	// Should still have only one user
	err = db.Model(&model.User{}).Count(&count).Error
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestCreateDefaultAdmin_WithoutAdminRole(t *testing.T) {
	db := setupTestDB(t)

	// Don't seed roles
	err := CreateDefaultAdmin(db)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "admin role not found")
}

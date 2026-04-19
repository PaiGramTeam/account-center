package initialize

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"paigram/internal/casbin"
	"paigram/internal/config"
	"paigram/internal/model"
	"paigram/internal/testutil"
)

func setupInitializerTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	return testutil.OpenMySQLTestDB(t, "initializer",
		&model.Permission{},
		&model.Role{},
		&model.RolePermission{},
		&model.User{},
		&model.UserRole{},
		&model.UserProfile{},
		&model.UserEmail{},
		&model.UserCredential{},
	)
}

func TestInitializerRunAutoSeedCreatesAdminAndCasbinPolicies(t *testing.T) {
	db := setupInitializerTestDB(t)
	casbin.Reset()
	t.Cleanup(casbin.Reset)

	t.Setenv("ADMIN_EMAIL", "bootstrap-admin@example.com")
	t.Setenv("ADMIN_PASSWORD", "BootstrapPass123!")
	t.Setenv("ADMIN_NAME", "Bootstrap Admin")

	initializer := NewInitializer(db, nil, config.DatabaseConfig{AutoSeed: true})
	require.NoError(t, initializer.Run())

	var adminRole model.Role
	require.NoError(t, db.Where("name = ?", model.RoleAdmin).First(&adminRole).Error)

	hasPolicy, err := casbin.GetEnforcer().Enforce(strconv.FormatUint(adminRole.ID, 10), "/api/v1/admin/roles/1/permissions", "PUT")
	require.NoError(t, err)
	assert.True(t, hasPolicy)

	var adminUser model.User
	require.NoError(t, db.First(&adminUser).Error)
	assert.Equal(t, model.UserStatusActive, adminUser.Status)

	var userRole model.UserRole
	require.NoError(t, db.Where("user_id = ?", adminUser.ID).First(&userRole).Error)
	assert.Equal(t, adminRole.ID, userRole.RoleID)
}

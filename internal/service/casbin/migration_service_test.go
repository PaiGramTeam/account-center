package casbin

import (
	"fmt"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	internalcasbin "paigram/internal/casbin"
)

func TestMigratePermissionsToCasbinPreservesCustomPolicies(t *testing.T) {
	internalcasbin.Reset()
	t.Cleanup(internalcasbin.Reset)

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, createTestRolesTable(db))
	require.NoError(t, db.Exec("CREATE TABLE IF NOT EXISTS permissions (id INTEGER PRIMARY KEY, name TEXT NOT NULL)").Error)
	require.NoError(t, db.Exec("CREATE TABLE IF NOT EXISTS role_permissions (role_id INTEGER NOT NULL, permission_id INTEGER NOT NULL)").Error)
	require.NoError(t, db.Exec("INSERT INTO roles (id, name, display_name) VALUES (?, ?, ?)", 11, "role-11", "Role 11").Error)
	require.NoError(t, db.Exec("INSERT INTO permissions (id, name) VALUES (?, ?)", 101, "role:manage").Error)
	require.NoError(t, db.Exec("INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)", 11, 101).Error)

	_, err = internalcasbin.InitEnforcer(db)
	require.NoError(t, err)

	enforcer := internalcasbin.GetEnforcer()
	_, err = enforcer.AddPolicy("11", "/api/v1/custom/authority-policy", "GET")
	require.NoError(t, err)
	require.NoError(t, enforcer.LoadPolicy())

	service := &CasbinService{db: db}
	require.NoError(t, service.MigratePermissionsToCasbin())

	policies := enforcer.GetFilteredPolicy(0, fmt.Sprint(11))
	assert.Contains(t, policies, []string{"11", "/api/v1/custom/authority-policy", "GET"})
	assert.Contains(t, policies, []string{"11", "/api/v1/authorities/:id/users", "GET"})
	assert.NotContains(t, policies, []string{"11", "/api/v1/casbin/authorities/:id/policies", "GET"})
	assert.NotContains(t, policies, []string{"11", "/api/v1/casbin/authorities/:id/policies", "PUT"})
}

func TestMigratePermissionsToCasbinMapsLegacyUserManageToSessionAndSecurityRoutes(t *testing.T) {
	internalcasbin.Reset()
	t.Cleanup(internalcasbin.Reset)

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, createTestRolesTable(db))
	require.NoError(t, db.Exec("CREATE TABLE IF NOT EXISTS permissions (id INTEGER PRIMARY KEY, name TEXT NOT NULL)").Error)
	require.NoError(t, db.Exec("CREATE TABLE IF NOT EXISTS role_permissions (role_id INTEGER NOT NULL, permission_id INTEGER NOT NULL)").Error)
	require.NoError(t, db.Exec("INSERT INTO roles (id, name, display_name) VALUES (?, ?, ?)", 21, "role-21", "Role 21").Error)
	require.NoError(t, db.Exec("INSERT INTO permissions (id, name) VALUES (?, ?)", 201, "user:manage").Error)
	require.NoError(t, db.Exec("INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)", 21, 201).Error)

	_, err = internalcasbin.InitEnforcer(db)
	require.NoError(t, err)

	service := &CasbinService{db: db}
	require.NoError(t, service.MigratePermissionsToCasbin())

	policies := internalcasbin.GetEnforcer().GetFilteredPolicy(0, fmt.Sprint(21))
	assert.Contains(t, policies, []string{"21", "/api/v1/users/:id/sessions", "GET"})
	assert.Contains(t, policies, []string{"21", "/api/v1/users/:id/sessions/:sessionId", "DELETE"})
	assert.Contains(t, policies, []string{"21", "/api/v1/users/:id/security-summary", "GET"})
	assert.NotContains(t, policies, []string{"21", "/api/v1/users/:id/login-logs", "GET"})
}

package casbin

import (
	"errors"
	"fmt"
	"testing"

	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	internalcasbin "paigram/internal/casbin"
)

func TestReplaceAuthorityPoliciesKeepsPreviousPoliciesOnInsertFailure(t *testing.T) {
	internalcasbin.Reset()
	t.Cleanup(internalcasbin.Reset)

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, createTestRolesTable(db))
	require.NoError(t, db.Exec("INSERT INTO roles (id, name, display_name) VALUES (?, ?, ?)", 7, "role-7", "Role 7").Error)

	_, err = internalcasbin.InitEnforcer(db)
	require.NoError(t, err)

	enforcer := internalcasbin.GetEnforcer()
	_, err = enforcer.AddPolicies([][]string{{"7", "/api/v1/authorities", "GET"}})
	require.NoError(t, err)
	require.NoError(t, enforcer.LoadPolicy())

	callbackName := "test:fail-casbin-policy-create"
	db.Callback().Create().Before("gorm:create").Register(callbackName, func(tx *gorm.DB) {
		rule, ok := tx.Statement.Dest.(*gormadapter.CasbinRule)
		if !ok {
			return
		}
		if rule.V0 == "7" && rule.V1 == "/api/v1/casbin/authorities/:id/policies" {
			tx.AddError(errors.New("forced create failure"))
		}
	})
	t.Cleanup(func() {
		_ = db.Callback().Create().Remove(callbackName)
	})

	service := &CasbinService{db: db}
	err = service.ReplaceAuthorityPolicies(7, []CasbinPolicyInfo{{
		Path:   "/api/v1/casbin/authorities/:id/policies",
		Method: "GET",
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forced create failure")

	require.NoError(t, enforcer.LoadPolicy())
	assert.Equal(t, [][]string{{"7", "/api/v1/authorities", "GET"}}, enforcer.GetFilteredPolicy(0, fmt.Sprint(7)))
	assert.False(t, enforcer.HasPolicy("7", "/api/v1/casbin/authorities/:id/policies", "GET"))
}

func TestReplaceAuthorityPoliciesRestoresPreviousPoliciesOnLoadFailure(t *testing.T) {
	internalcasbin.Reset()
	t.Cleanup(internalcasbin.Reset)

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, createTestRolesTable(db))
	require.NoError(t, db.Exec("INSERT INTO roles (id, name, display_name) VALUES (?, ?, ?)", 9, "role-9", "Role 9").Error)

	_, err = internalcasbin.InitEnforcer(db)
	require.NoError(t, err)

	enforcer := internalcasbin.GetEnforcer()
	_, err = enforcer.AddPolicies([][]string{{"9", "/api/v1/authorities", "GET"}})
	require.NoError(t, err)
	require.NoError(t, enforcer.LoadPolicy())

	callbackName := "test:fail-casbin-policy-load"
	var failLoads bool = true
	db.Callback().Query().Before("gorm:query").Register(callbackName, func(tx *gorm.DB) {
		if !failLoads {
			return
		}
		if tx.Statement != nil && tx.Statement.Schema != nil && tx.Statement.Schema.Table == (gormadapter.CasbinRule{}).TableName() {
			tx.AddError(errors.New("forced load failure"))
		}
	})
	t.Cleanup(func() {
		_ = db.Callback().Query().Remove(callbackName)
	})

	service := &CasbinService{db: db}
	err = service.ReplaceAuthorityPolicies(9, []CasbinPolicyInfo{{
		Path:   "/api/v1/casbin/authorities/:id/policies",
		Method: "GET",
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forced load failure")

	failLoads = false
	require.NoError(t, enforcer.LoadPolicy())
	assert.Equal(t, [][]string{{"9", "/api/v1/authorities", "GET"}}, enforcer.GetFilteredPolicy(0, fmt.Sprint(9)))
	assert.False(t, enforcer.HasPolicy("9", "/api/v1/casbin/authorities/:id/policies", "GET"))
}

func createTestRolesTable(db *gorm.DB) error {
	return db.Exec("CREATE TABLE IF NOT EXISTS roles (id INTEGER PRIMARY KEY, name TEXT NOT NULL, display_name TEXT NOT NULL, deleted_at DATETIME NULL)").Error
}

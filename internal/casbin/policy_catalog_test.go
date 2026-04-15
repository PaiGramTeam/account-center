package casbin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/model"
)

func TestPoliciesForPermissionUserReadDoesNotSpillIntoPrivilegedSubresources(t *testing.T) {
	rules := PoliciesForPermission(model.BuildPermissionName(model.ResourceUser, model.ActionRead))
	require.NotEmpty(t, rules)

	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/users", Method: "GET"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/users/:id", Method: "GET"})

	assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/users/me", Method: "GET"})
	assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/users/:id/roles", Method: "GET"})
	assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/users/:id/roles", Method: "POST"})
	assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/users/:id/permissions", Method: "GET"})
	assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/users/:id/audit-logs", Method: "GET"})
	assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/users/:id/login-logs", Method: "GET"})
	assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/users/:id/sessions", Method: "GET"})
	assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/users/:id/sessions/:sessionId", Method: "DELETE"})
}

func TestPoliciesForSystemRoleAdminIncludesAuthorityAndCasbinRoutesWithoutBroadWildcards(t *testing.T) {
	rules := PoliciesForSystemRole(model.RoleAdmin)
	require.NotEmpty(t, rules)

	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/authorities", Method: "GET"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/authorities", Method: "POST"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/authorities/:id", Method: "GET"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/authorities/:id", Method: "PUT"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/authorities/:id", Method: "DELETE"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/authorities/:id/permissions", Method: "GET"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/authorities/:id/permissions", Method: "POST"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/authorities/:id/users", Method: "GET"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/authorities/:id/users", Method: "PUT"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/casbin/authorities/:id/policies", Method: "GET"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/casbin/authorities/:id/policies", Method: "PUT"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/profiles/:id", Method: "GET"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/profiles/:id", Method: "PATCH"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/users/:id/status", Method: "PATCH"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/users/:id/reset-password", Method: "POST"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/users/:id/audit-logs", Method: "GET"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/users/:id/login-logs", Method: "GET"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/users/:id/roles", Method: "GET"})
	assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/users/:id/roles", Method: "POST"})
	assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/users/:id/roles/:roleId", Method: "DELETE"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/users/:id/permissions", Method: "GET"})
	assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/roles", Method: "GET"})
	assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/roles/:id", Method: "GET"})
	assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/permissions", Method: "GET"})
	assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/permissions/:id", Method: "GET"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/users/:id/sessions", Method: "GET"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/users/:id/sessions/:sessionId", Method: "DELETE"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/users/:id/security-summary", Method: "GET"})
	assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/menu", Method: "GET"})
	assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/users/me", Method: "GET"})

	for _, rule := range rules {
		assert.NotEqual(t, "/api/v1/*", rule.Path)
		assert.NotEqual(t, "/api/v1/users/*", rule.Path)
		assert.NotEqual(t, "/api/v1/authorities/*", rule.Path)
	}
}

func TestPoliciesForPermissionCoversSeededCatalogRoutes(t *testing.T) {
	testCases := []struct {
		name       string
		permission string
		contains   []PolicyRule
	}{
		{
			name:       "role read",
			permission: model.BuildPermissionName(model.ResourceRole, model.ActionRead),
			contains: []PolicyRule{
				{Path: "/api/v1/authorities", Method: "GET"},
				{Path: "/api/v1/users/:id/roles", Method: "GET"},
			},
		},
		{
			name:       "role manage",
			permission: model.BuildPermissionName(model.ResourceRole, model.ActionManage),
			contains: []PolicyRule{
				{Path: "/api/v1/authorities/:id/users", Method: "GET"},
				{Path: "/api/v1/authorities/:id/users", Method: "PUT"},
			},
		},
		{
			name:       "permission read",
			permission: model.BuildPermissionName(model.ResourcePermission, model.ActionRead),
			contains: []PolicyRule{
				{Path: "/api/v1/users/:id/permissions", Method: "GET"},
			},
		},
		{
			name:       "session delete",
			permission: model.BuildPermissionName(model.ResourceSession, model.ActionDelete),
			contains:   []PolicyRule{{Path: "/api/v1/users/:id/sessions/:sessionId", Method: "DELETE"}},
		},
		{
			name:       "audit read",
			permission: model.BuildPermissionName(model.ResourceAudit, model.ActionRead),
			contains: []PolicyRule{
				{Path: "/api/v1/users/:id/audit-logs", Method: "GET"},
				{Path: "/api/v1/users/:id/login-logs", Method: "GET"},
			},
		},
		{
			name:       "user read derived routes",
			permission: model.BuildPermissionName(model.ResourceUser, model.ActionRead),
			contains: []PolicyRule{
				{Path: "/api/v1/profiles/:id", Method: "GET"},
				{Path: "/api/v1/users/:id/security-summary", Method: "GET"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rules := PoliciesForPermission(tc.permission)
			require.NotNil(t, rules)
			for _, rule := range tc.contains {
				assert.Contains(t, rules, rule)
			}
			if tc.permission == model.BuildPermissionName(model.ResourceRole, model.ActionManage) {
				assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/casbin/authorities/:id/policies", Method: "GET"})
				assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/casbin/authorities/:id/policies", Method: "PUT"})
				assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/users/:id/roles", Method: "POST"})
				assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/users/:id/roles/:roleId", Method: "DELETE"})
			}
		})
	}

	assert.Empty(t, PoliciesForPermission(model.BuildPermissionName(model.ResourceBot, model.ActionRead)))
}

func TestPoliciesForSystemRoleModeratorDerivedFromSeedPermissions(t *testing.T) {
	rules := PoliciesForSystemRole(model.RoleModerator)
	require.NotEmpty(t, rules)

	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/users", Method: "GET"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/users/:id", Method: "GET"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/profiles/:id", Method: "GET"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/users/:id", Method: "PATCH"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/profiles/:id", Method: "PATCH"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/users/:id/sessions", Method: "GET"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/users/:id/security-summary", Method: "GET"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/users/:id/audit-logs", Method: "GET"})
	assert.Contains(t, rules, PolicyRule{Path: "/api/v1/users/:id/login-logs", Method: "GET"})
	assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/authorities", Method: "POST"})
	assert.NotContains(t, rules, PolicyRule{Path: "/api/v1/users/:id", Method: "DELETE"})
}

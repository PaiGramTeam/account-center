package casbin

import "paigram/internal/model"

// PolicyRule describes one explicit Casbin path and method pair.
type PolicyRule struct {
	Path   string
	Method string
}

var adminOnlyPolicies = []PolicyRule{
	{Path: "/api/v1/casbin/authorities/:id/policies", Method: "GET"},
	{Path: "/api/v1/casbin/authorities/:id/policies", Method: "PUT"},
}

var permissionPolicies = map[string][]PolicyRule{
	model.BuildPermissionName(model.ResourceUser, model.ActionCreate): {
		{Path: "/api/v1/users", Method: "POST"},
	},
	model.BuildPermissionName(model.ResourceUser, model.ActionRead): {
		{Path: "/api/v1/users", Method: "GET"},
		{Path: "/api/v1/users/:id", Method: "GET"},
		{Path: "/api/v1/profiles/:id", Method: "GET"},
		{Path: "/api/v1/users/:id/security-summary", Method: "GET"},
	},
	model.BuildPermissionName(model.ResourceUser, model.ActionUpdate): {
		{Path: "/api/v1/users/:id", Method: "PATCH"},
		{Path: "/api/v1/users/:id/status", Method: "PATCH"},
		{Path: "/api/v1/users/:id/reset-password", Method: "POST"},
		{Path: "/api/v1/profiles/:id", Method: "PATCH"},
	},
	model.BuildPermissionName(model.ResourceUser, model.ActionDelete): {
		{Path: "/api/v1/users/:id", Method: "DELETE"},
	},
	model.BuildPermissionName(model.ResourceUser, model.ActionList): {
		{Path: "/api/v1/users", Method: "GET"},
	},
	model.BuildPermissionName(model.ResourceRole, model.ActionCreate): {
		{Path: "/api/v1/authorities", Method: "POST"},
	},
	model.BuildPermissionName(model.ResourceRole, model.ActionRead): {
		{Path: "/api/v1/authorities", Method: "GET"},
		{Path: "/api/v1/authorities/:id", Method: "GET"},
		{Path: "/api/v1/users/:id/roles", Method: "GET"},
	},
	model.BuildPermissionName(model.ResourceRole, model.ActionUpdate): {
		{Path: "/api/v1/authorities/:id", Method: "PUT"},
	},
	model.BuildPermissionName(model.ResourceRole, model.ActionDelete): {
		{Path: "/api/v1/authorities/:id", Method: "DELETE"},
	},
	model.BuildPermissionName(model.ResourceRole, model.ActionList): {
		{Path: "/api/v1/authorities", Method: "GET"},
	},
	model.BuildPermissionName(model.ResourceRole, model.ActionManage): {
		{Path: "/api/v1/authorities/:id/users", Method: "GET"},
		{Path: "/api/v1/authorities/:id/users", Method: "PUT"},
		{Path: "/api/v1/authorities/:id/permissions", Method: "GET"},
		{Path: "/api/v1/authorities/:id/permissions", Method: "POST"},
	},
	model.BuildPermissionName(model.ResourcePermission, model.ActionCreate): {},
	model.BuildPermissionName(model.ResourcePermission, model.ActionRead): {
		{Path: "/api/v1/users/:id/permissions", Method: "GET"},
	},
	model.BuildPermissionName(model.ResourcePermission, model.ActionDelete): {},
	model.BuildPermissionName(model.ResourcePermission, model.ActionList): {
		{Path: "/api/v1/users/:id/permissions", Method: "GET"},
	},
	model.BuildPermissionName(model.ResourcePlatform, model.ActionCreate): {
		{Path: "/api/v1/platform-services", Method: "POST"},
	},
	model.BuildPermissionName(model.ResourcePlatform, model.ActionRead): {
		{Path: "/api/v1/platform-services", Method: "GET"},
		{Path: "/api/v1/platform-services/:id", Method: "GET"},
		{Path: "/api/v1/platform-services/:id/check", Method: "POST"},
	},
	model.BuildPermissionName(model.ResourcePlatform, model.ActionUpdate): {
		{Path: "/api/v1/platform-services/:id", Method: "PATCH"},
	},
	model.BuildPermissionName(model.ResourcePlatform, model.ActionDelete): {
		{Path: "/api/v1/platform-services/:id", Method: "DELETE"},
	},
	model.BuildPermissionName(model.ResourcePlatform, model.ActionList): {
		{Path: "/api/v1/platform-services", Method: "GET"},
	},
	model.BuildPermissionName(model.ResourcePlatform, model.ActionManage): {},
	model.BuildPermissionName(model.ResourcePlatformAccount, model.ActionRead): {
		{Path: "/api/v1/admin/platform-accounts/:bindingId", Method: "GET"},
		{Path: "/api/v1/admin/platform-accounts/:bindingId/profiles", Method: "GET"},
		{Path: "/api/v1/admin/platform-accounts/:bindingId/consumer-grants", Method: "GET"},
	},
	model.BuildPermissionName(model.ResourcePlatformAccount, model.ActionList): {
		{Path: "/api/v1/admin/platform-accounts", Method: "GET"},
	},
	model.BuildPermissionName(model.ResourcePlatformAccount, model.ActionUpdate): {
		{Path: "/api/v1/admin/platform-accounts/:bindingId/consumer-grants/:consumer", Method: "PUT"},
		{Path: "/api/v1/admin/platform-accounts/:bindingId/refresh", Method: "POST"},
	},
	model.BuildPermissionName(model.ResourcePlatformAccount, model.ActionDelete): {
		{Path: "/api/v1/admin/platform-accounts/:bindingId", Method: "DELETE"},
	},
	model.BuildPermissionName(model.ResourceBot, model.ActionCreate): {},
	model.BuildPermissionName(model.ResourceBot, model.ActionRead):   {},
	model.BuildPermissionName(model.ResourceBot, model.ActionUpdate): {},
	model.BuildPermissionName(model.ResourceBot, model.ActionDelete): {},
	model.BuildPermissionName(model.ResourceBot, model.ActionList):   {},
	model.BuildPermissionName(model.ResourceBot, model.ActionManage): {},
	model.BuildPermissionName(model.ResourceSession, model.ActionRead): {
		{Path: "/api/v1/users/:id/sessions", Method: "GET"},
	},
	model.BuildPermissionName(model.ResourceSession, model.ActionDelete): {
		{Path: "/api/v1/users/:id/sessions/:sessionId", Method: "DELETE"},
	},
	model.BuildPermissionName(model.ResourceSession, model.ActionList): {
		{Path: "/api/v1/users/:id/sessions", Method: "GET"},
	},
	model.BuildPermissionName(model.ResourceAudit, model.ActionRead): {
		{Path: "/api/v1/users/:id/audit-logs", Method: "GET"},
		{Path: "/api/v1/users/:id/login-logs", Method: "GET"},
	},
	model.BuildPermissionName(model.ResourceAudit, model.ActionList): {
		{Path: "/api/v1/users/:id/audit-logs", Method: "GET"},
		{Path: "/api/v1/users/:id/login-logs", Method: "GET"},
	},
}

var systemRolePermissions = map[string][]string{
	model.RoleAdmin: {
		"user:create", "user:read", "user:update", "user:delete", "user:list",
		"role:create", "role:read", "role:update", "role:delete", "role:list", "role:manage",
		"permission:create", "permission:read", "permission:delete", "permission:list",
		model.PermPlatformCreate, model.PermPlatformRead, model.PermPlatformUpdate, model.PermPlatformDelete, model.PermPlatformList, model.PermPlatformManage,
		model.PermPlatformAccountRead, model.PermPlatformAccountList, model.PermPlatformAccountUpdate, model.PermPlatformAccountDelete,
		"bot:create", "bot:read", "bot:update", "bot:delete", "bot:list", "bot:manage",
		"session:read", "session:delete", "session:list",
		"audit:read", "audit:list",
	},
	model.RoleModerator: {
		"user:read", "user:update", "user:list",
		"bot:read", "bot:list",
		"session:read", "session:list",
		"audit:read", "audit:list",
	},
	model.RoleUser: {
		"user:read",
		"bot:read", "bot:list",
	},
	model.RoleGuest: {},
}

// PoliciesForPermission returns the explicit API rules for a permission.
func PoliciesForPermission(permission string) []PolicyRule {
	rules, ok := permissionPolicies[permission]
	if !ok {
		return nil
	}
	return append([]PolicyRule(nil), rules...)
}

// PoliciesForSystemRole returns explicit seed rules for built-in system roles.
func PoliciesForSystemRole(role string) []PolicyRule {
	permissions := PermissionNamesForSystemRole(role)
	if permissions == nil {
		return nil
	}

	rules := make([]PolicyRule, 0)
	for _, permission := range permissions {
		rules = append(rules, PoliciesForPermission(permission)...)
	}
	if role == model.RoleAdmin {
		rules = append(rules, adminOnlyPolicies...)
	}

	return uniquePolicyRules(rules)
}

// AllManagedPolicies returns every explicit policy rule derived from the catalog.
func AllManagedPolicies() []PolicyRule {
	rules := make([]PolicyRule, 0)
	for _, permissionRules := range permissionPolicies {
		rules = append(rules, permissionRules...)
	}
	rules = append(rules, adminOnlyPolicies...)
	return uniquePolicyRules(rules)
}

// PermissionNamesForSystemRole exposes the seeded permission set for built-in roles.
func PermissionNamesForSystemRole(role string) []string {
	permissions, ok := systemRolePermissions[role]
	if !ok {
		return nil
	}
	return append([]string(nil), permissions...)
}

func uniquePolicyRules(rules []PolicyRule) []PolicyRule {
	seen := make(map[PolicyRule]struct{}, len(rules))
	unique := make([]PolicyRule, 0, len(rules))
	for _, rule := range rules {
		if _, ok := seen[rule]; ok {
			continue
		}
		seen[rule] = struct{}{}
		unique = append(unique, rule)
	}
	return unique
}

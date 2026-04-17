package seed

import (
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"

	"gorm.io/gorm"

	"paigram/internal/casbin"
	"paigram/internal/model"
)

// PolicyDrift reports managed Casbin policy mismatches for one seeded system role.
type PolicyDrift struct {
	RoleName   string
	RoleID     string
	Missing    [][]string
	Unexpected [][]string
}

// DefaultPermissions defines the default permissions in the system.
var DefaultPermissions = []struct {
	Name        string
	Resource    string
	Action      string
	Description string
}{
	// User permissions
	{model.BuildPermissionName(model.ResourceUser, model.ActionCreate), model.ResourceUser, model.ActionCreate, "Create new users"},
	{model.BuildPermissionName(model.ResourceUser, model.ActionRead), model.ResourceUser, model.ActionRead, "View user information"},
	{model.BuildPermissionName(model.ResourceUser, model.ActionUpdate), model.ResourceUser, model.ActionUpdate, "Update user information"},
	{model.BuildPermissionName(model.ResourceUser, model.ActionDelete), model.ResourceUser, model.ActionDelete, "Delete users"},
	{model.BuildPermissionName(model.ResourceUser, model.ActionList), model.ResourceUser, model.ActionList, "List all users"},

	// Role permissions
	{model.BuildPermissionName(model.ResourceRole, model.ActionCreate), model.ResourceRole, model.ActionCreate, "Create new roles"},
	{model.BuildPermissionName(model.ResourceRole, model.ActionRead), model.ResourceRole, model.ActionRead, "View role information"},
	{model.BuildPermissionName(model.ResourceRole, model.ActionUpdate), model.ResourceRole, model.ActionUpdate, "Update role information"},
	{model.BuildPermissionName(model.ResourceRole, model.ActionDelete), model.ResourceRole, model.ActionDelete, "Delete roles"},
	{model.BuildPermissionName(model.ResourceRole, model.ActionList), model.ResourceRole, model.ActionList, "List all roles"},
	{model.BuildPermissionName(model.ResourceRole, model.ActionManage), model.ResourceRole, model.ActionManage, "Manage role assignments"},

	// Permission permissions
	{model.BuildPermissionName(model.ResourcePermission, model.ActionCreate), model.ResourcePermission, model.ActionCreate, "Create new permissions"},
	{model.BuildPermissionName(model.ResourcePermission, model.ActionRead), model.ResourcePermission, model.ActionRead, "View permission information"},
	{model.BuildPermissionName(model.ResourcePermission, model.ActionDelete), model.ResourcePermission, model.ActionDelete, "Delete permissions"},
	{model.BuildPermissionName(model.ResourcePermission, model.ActionList), model.ResourcePermission, model.ActionList, "List all permissions"},

	// Platform permissions
	{model.BuildPermissionName(model.ResourcePlatform, model.ActionCreate), model.ResourcePlatform, model.ActionCreate, "Create platform registrations"},
	{model.BuildPermissionName(model.ResourcePlatform, model.ActionRead), model.ResourcePlatform, model.ActionRead, "View platform registration information"},
	{model.BuildPermissionName(model.ResourcePlatform, model.ActionUpdate), model.ResourcePlatform, model.ActionUpdate, "Update platform registrations"},
	{model.BuildPermissionName(model.ResourcePlatform, model.ActionDelete), model.ResourcePlatform, model.ActionDelete, "Delete platform registrations"},
	{model.BuildPermissionName(model.ResourcePlatform, model.ActionList), model.ResourcePlatform, model.ActionList, "List platform registrations"},
	{model.BuildPermissionName(model.ResourcePlatform, model.ActionManage), model.ResourcePlatform, model.ActionManage, "Manage platform registrations"},

	// Bot permissions
	{model.BuildPermissionName(model.ResourceBot, model.ActionCreate), model.ResourceBot, model.ActionCreate, "Create new bots"},
	{model.BuildPermissionName(model.ResourceBot, model.ActionRead), model.ResourceBot, model.ActionRead, "View bot information"},
	{model.BuildPermissionName(model.ResourceBot, model.ActionUpdate), model.ResourceBot, model.ActionUpdate, "Update bot information"},
	{model.BuildPermissionName(model.ResourceBot, model.ActionDelete), model.ResourceBot, model.ActionDelete, "Delete bots"},
	{model.BuildPermissionName(model.ResourceBot, model.ActionList), model.ResourceBot, model.ActionList, "List all bots"},
	{model.BuildPermissionName(model.ResourceBot, model.ActionManage), model.ResourceBot, model.ActionManage, "Manage bot tokens"},

	// Session permissions
	{model.BuildPermissionName(model.ResourceSession, model.ActionRead), model.ResourceSession, model.ActionRead, "View session information"},
	{model.BuildPermissionName(model.ResourceSession, model.ActionDelete), model.ResourceSession, model.ActionDelete, "Revoke sessions"},
	{model.BuildPermissionName(model.ResourceSession, model.ActionList), model.ResourceSession, model.ActionList, "List all sessions"},

	// Audit permissions
	{model.BuildPermissionName(model.ResourceAudit, model.ActionRead), model.ResourceAudit, model.ActionRead, "View audit logs"},
	{model.BuildPermissionName(model.ResourceAudit, model.ActionList), model.ResourceAudit, model.ActionList, "List audit logs"},
}

// DefaultRoles defines the default roles and their permissions.
var DefaultRoles = []struct {
	Name        string
	DisplayName string
	Description string
	IsSystem    bool
	Permissions []string
}{
	{
		Name:        model.RoleAdmin,
		DisplayName: "Administrator",
		Description: "Full system access with all permissions",
		IsSystem:    true,
		Permissions: casbin.PermissionNamesForSystemRole(model.RoleAdmin),
	},
	{
		Name:        model.RoleModerator,
		DisplayName: "Moderator",
		Description: "Limited administrative access for user and content management",
		IsSystem:    true,
		Permissions: casbin.PermissionNamesForSystemRole(model.RoleModerator),
	},
	{
		Name:        model.RoleUser,
		DisplayName: "Regular User",
		Description: "Standard user with basic access",
		IsSystem:    true,
		Permissions: casbin.PermissionNamesForSystemRole(model.RoleUser),
	},
	{
		Name:        model.RoleGuest,
		DisplayName: "Guest",
		Description: "Limited read-only access",
		IsSystem:    true,
		Permissions: casbin.PermissionNamesForSystemRole(model.RoleGuest),
	},
}

// SeedPermissions creates default permissions if they don't exist.
func SeedPermissions(db *gorm.DB) error {
	for _, p := range DefaultPermissions {
		var existing model.Permission
		err := db.Where("name = ?", p.Name).First(&existing).Error

		if err == nil {
			// Permission already exists, skip
			continue
		}

		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("check permission %s: %w", p.Name, err)
		}

		// Create permission
		perm := model.Permission{
			Name:        p.Name,
			Resource:    p.Resource,
			Action:      p.Action,
			Description: p.Description,
		}

		if err := db.Create(&perm).Error; err != nil {
			return fmt.Errorf("create permission %s: %w", p.Name, err)
		}

		log.Printf("Created permission: %s", p.Name)
	}

	return nil
}

// SeedRoles creates default roles and assigns permissions if they don't exist.
func SeedRoles(db *gorm.DB) error {
	for _, r := range DefaultRoles {
		var role model.Role
		err := db.Where("name = ?", r.Name).First(&role).Error

		if err == nil {
			// Role already exists, update permissions
			if err := updateRolePermissions(db, &role, r.Permissions); err != nil {
				return fmt.Errorf("update role %s permissions: %w", r.Name, err)
			}
			log.Printf("Updated role: %s", r.Name)
			continue
		}

		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("check role %s: %w", r.Name, err)
		}

		// Create role
		role = model.Role{
			Name:        r.Name,
			DisplayName: r.DisplayName,
			Description: r.Description,
			IsSystem:    r.IsSystem,
		}

		if err := db.Create(&role).Error; err != nil {
			return fmt.Errorf("create role %s: %w", r.Name, err)
		}

		log.Printf("Created role: %s", r.Name)

		// Assign permissions
		if err := updateRolePermissions(db, &role, r.Permissions); err != nil {
			return fmt.Errorf("assign permissions to role %s: %w", r.Name, err)
		}
	}

	return nil
}

// updateRolePermissions assigns permissions to a role.
func updateRolePermissions(db *gorm.DB, role *model.Role, permissionNames []string) error {
	var permissions []model.Permission
	if len(permissionNames) > 0 {
		if err := db.Where("name IN ?", permissionNames).Find(&permissions).Error; err != nil {
			return fmt.Errorf("find permissions: %w", err)
		}

		if len(permissions) != len(permissionNames) {
			return fmt.Errorf("some permissions not found (expected %d, found %d)", len(permissionNames), len(permissions))
		}
	}

	// Replace all permissions for this role
	if err := db.Model(role).Association("Permissions").Replace(&permissions); err != nil {
		return fmt.Errorf("assign permissions: %w", err)
	}

	return nil
}

// SeedCasbinPolicies adds Casbin policy seed data for default roles.
func SeedCasbinPolicies(db *gorm.DB) error {
	log.Println("Seeding Casbin policies...")

	enforcer, err := casbin.InitEnforcer(db)
	if err != nil {
		return fmt.Errorf("init casbin enforcer: %w", err)
	}

	desiredPoliciesByRole, _, totalDesired, err := desiredSeedPoliciesByRole(db)
	if err != nil {
		return err
	}

	removedCount, addedCount, err := reconcileSeedPolicies(enforcer, desiredPoliciesByRole)
	if err != nil {
		return fmt.Errorf("failed to add casbin policies: %w", err)
	}

	log.Printf("Casbin policies reconciled: removed %d, added %d, desired %d", removedCount, addedCount, totalDesired)
	return nil
}

// VerifySeedCasbinPolicies checks built-in role policies against the seed catalog.
func VerifySeedCasbinPolicies(db *gorm.DB) ([]PolicyDrift, error) {
	enforcer, err := casbin.InitEnforcer(db)
	if err != nil {
		return nil, fmt.Errorf("init casbin enforcer: %w", err)
	}

	desiredPoliciesByRole, roleNamesByID, _, err := desiredSeedPoliciesByRole(db)
	if err != nil {
		return nil, err
	}

	drift := make([]PolicyDrift, 0)
	for roleID, desiredPolicies := range desiredPoliciesByRole {
		missing, unexpected := diffPolicies(enforcer.GetFilteredPolicy(0, roleID), desiredPolicies)
		if len(missing) == 0 && len(unexpected) == 0 {
			continue
		}

		drift = append(drift, PolicyDrift{
			RoleName:   roleNamesByID[roleID],
			RoleID:     roleID,
			Missing:    missing,
			Unexpected: unexpected,
		})
	}

	sort.Slice(drift, func(i, j int) bool {
		return drift[i].RoleName < drift[j].RoleName
	})

	return drift, nil
}

func desiredSeedPoliciesByRole(db *gorm.DB) (map[string][][]string, map[string]string, int, error) {
	desiredPoliciesByRole := make(map[string][][]string)
	roleNamesByID := make(map[string]string)
	totalDesired := 0

	for _, roleDef := range DefaultRoles {
		if !roleDef.IsSystem {
			continue
		}

		var role model.Role
		if err := db.Where("name = ?", roleDef.Name).First(&role).Error; err != nil {
			return nil, nil, 0, fmt.Errorf("%s role not found: %w", roleDef.Name, err)
		}

		roleID := strconv.FormatUint(role.ID, 10)
		policies := buildSeedPolicies(roleID, casbin.PoliciesForSystemRole(roleDef.Name))
		desiredPoliciesByRole[roleID] = policies
		roleNamesByID[roleID] = roleDef.Name
		totalDesired += len(policies)
	}

	return desiredPoliciesByRole, roleNamesByID, totalDesired, nil
}

func buildSeedPolicies(roleID string, rules []casbin.PolicyRule) [][]string {
	policies := make([][]string, 0, len(rules))
	for _, rule := range rules {
		policies = append(policies, []string{roleID, rule.Path, rule.Method})
	}
	return policies
}

func reconcileSeedPolicies(enforcer interface {
	GetFilteredPolicy(fieldIndex int, fieldValues ...string) [][]string
	RemovePolicy(params ...interface{}) (bool, error)
	AddPolicy(params ...interface{}) (bool, error)
	LoadPolicy() error
}, desiredByRole map[string][][]string) (int, int, error) {
	removedCount := 0
	addedCount := 0
	for roleID, desiredPolicies := range desiredByRole {
		desiredSet := make(map[string]struct{}, len(desiredPolicies))
		for _, policy := range desiredPolicies {
			desiredSet[policyKey(policy[0], policy[1], policy[2])] = struct{}{}
		}

		for _, existing := range enforcer.GetFilteredPolicy(0, roleID) {
			if _, ok := desiredSet[policyKey(existing[0], existing[1], existing[2])]; ok {
				continue
			}
			removed, err := enforcer.RemovePolicy(existing[0], existing[1], existing[2])
			if err != nil {
				return removedCount, addedCount, err
			}
			if removed {
				removedCount++
			}
		}

		for _, policy := range desiredPolicies {
			added, err := enforcer.AddPolicy(policy[0], policy[1], policy[2])
			if err != nil {
				return removedCount, addedCount, err
			}
			if added {
				addedCount++
			}
		}
	}

	if err := enforcer.LoadPolicy(); err != nil {
		return removedCount, addedCount, err
	}

	return removedCount, addedCount, nil
}

func diffPolicies(actualPolicies, desiredPolicies [][]string) ([][]string, [][]string) {
	actualSet := make(map[string][]string, len(actualPolicies))
	for _, policy := range actualPolicies {
		actualSet[policyKey(policy[0], policy[1], policy[2])] = append([]string(nil), policy...)
	}

	desiredSet := make(map[string][]string, len(desiredPolicies))
	for _, policy := range desiredPolicies {
		desiredSet[policyKey(policy[0], policy[1], policy[2])] = append([]string(nil), policy...)
	}

	missing := make([][]string, 0)
	for key, policy := range desiredSet {
		if _, ok := actualSet[key]; ok {
			continue
		}
		missing = append(missing, policy)
	}

	unexpected := make([][]string, 0)
	for key, policy := range actualSet {
		if _, ok := desiredSet[key]; ok {
			continue
		}
		unexpected = append(unexpected, policy)
	}

	sortPolicyTuples(missing)
	sortPolicyTuples(unexpected)
	return missing, unexpected
}

func sortPolicyTuples(policies [][]string) {
	sort.Slice(policies, func(i, j int) bool {
		return policyKey(policies[i][0], policies[i][1], policies[i][2]) < policyKey(policies[j][0], policies[j][1], policies[j][2])
	})
}

func policyKey(sub, obj, act string) string {
	return sub + "\x00" + obj + "\x00" + act
}

// Run executes all seed functions in order.
func Run(db *gorm.DB) error {
	log.Println("Running seed data initialization...")

	if err := SeedPermissions(db); err != nil {
		return fmt.Errorf("seed permissions: %w", err)
	}

	if err := SeedRoles(db); err != nil {
		return fmt.Errorf("seed roles: %w", err)
	}

	if err := SeedCasbinPolicies(db); err != nil {
		return fmt.Errorf("seed casbin policies: %w", err)
	}

	log.Println("Seed data initialization completed successfully")
	return nil
}

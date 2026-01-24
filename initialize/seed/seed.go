package seed

import (
	"errors"
	"fmt"
	"log"

	"gorm.io/gorm"

	"paigram/internal/model"
)

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
		Permissions: []string{
			// All permissions
			"user:create", "user:read", "user:update", "user:delete", "user:list",
			"role:create", "role:read", "role:update", "role:delete", "role:list", "role:manage",
			"permission:create", "permission:read", "permission:delete", "permission:list",
			"bot:create", "bot:read", "bot:update", "bot:delete", "bot:list", "bot:manage",
			"session:read", "session:delete", "session:list",
			"audit:read", "audit:list",
		},
	},
	{
		Name:        model.RoleModerator,
		DisplayName: "Moderator",
		Description: "Limited administrative access for user and content management",
		IsSystem:    true,
		Permissions: []string{
			"user:read", "user:update", "user:list",
			"bot:read", "bot:list",
			"session:read", "session:list",
			"audit:read", "audit:list",
		},
	},
	{
		Name:        model.RoleUser,
		DisplayName: "Regular User",
		Description: "Standard user with basic access",
		IsSystem:    true,
		Permissions: []string{
			"user:read",
			"bot:read", "bot:list",
		},
	},
	{
		Name:        model.RoleGuest,
		DisplayName: "Guest",
		Description: "Limited read-only access",
		IsSystem:    true,
		Permissions: []string{},
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
	if len(permissionNames) == 0 {
		return nil
	}

	var permissions []model.Permission
	if err := db.Where("name IN ?", permissionNames).Find(&permissions).Error; err != nil {
		return fmt.Errorf("find permissions: %w", err)
	}

	if len(permissions) != len(permissionNames) {
		return fmt.Errorf("some permissions not found (expected %d, found %d)", len(permissionNames), len(permissions))
	}

	// Replace all permissions for this role
	if err := db.Model(role).Association("Permissions").Replace(&permissions); err != nil {
		return fmt.Errorf("assign permissions: %w", err)
	}

	return nil
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

	log.Println("Seed data initialization completed successfully")
	return nil
}

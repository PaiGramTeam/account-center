package permission

import (
	"errors"
	"fmt"

	"gorm.io/gorm"

	"paigram/internal/model"
)

var (
	// ErrPermissionDenied indicates the user lacks required permissions.
	ErrPermissionDenied = errors.New("permission denied")
	// ErrRoleNotFound indicates the role does not exist.
	ErrRoleNotFound = errors.New("role not found")
	// ErrPermissionNotFound indicates the permission does not exist.
	ErrPermissionNotFound = errors.New("permission not found")
	// ErrUserAlreadyHasRole indicates the user already has the role.
	ErrUserAlreadyHasRole = errors.New("user already has role")
	// ErrCannotDeleteSystemRole indicates system roles cannot be deleted.
	ErrCannotDeleteSystemRole = errors.New("cannot delete system role")
)

// Manager handles permission-related operations.
type Manager struct {
	db *gorm.DB
}

// NewManager creates a new permission manager instance.
func NewManager(db *gorm.DB) *Manager {
	return &Manager{db: db}
}

// CreatePermission creates a new permission.
func (m *Manager) CreatePermission(name, resource, action, description string) (*model.Permission, error) {
	perm := &model.Permission{
		Name:        name,
		Resource:    resource,
		Action:      action,
		Description: description,
	}

	if err := m.db.Create(perm).Error; err != nil {
		return nil, fmt.Errorf("create permission: %w", err)
	}

	return perm, nil
}

// GetPermissionByName retrieves a permission by its name.
func (m *Manager) GetPermissionByName(name string) (*model.Permission, error) {
	var perm model.Permission
	if err := m.db.Where("name = ?", name).First(&perm).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrPermissionNotFound
		}
		return nil, fmt.Errorf("get permission: %w", err)
	}
	return &perm, nil
}

// ListPermissions retrieves all permissions.
func (m *Manager) ListPermissions() ([]model.Permission, error) {
	var perms []model.Permission
	if err := m.db.Find(&perms).Error; err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	return perms, nil
}

// DeletePermission removes a permission by ID.
func (m *Manager) DeletePermission(id uint64) error {
	result := m.db.Delete(&model.Permission{}, id)
	if result.Error != nil {
		return fmt.Errorf("delete permission: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrPermissionNotFound
	}
	return nil
}

// CreateRole creates a new role.
func (m *Manager) CreateRole(name, displayName, description string, isSystem bool) (*model.Role, error) {
	role := &model.Role{
		Name:        name,
		DisplayName: displayName,
		Description: description,
		IsSystem:    isSystem,
	}

	if err := m.db.Create(role).Error; err != nil {
		return nil, fmt.Errorf("create role: %w", err)
	}

	return role, nil
}

// GetRoleByName retrieves a role by its name with permissions preloaded.
func (m *Manager) GetRoleByName(name string) (*model.Role, error) {
	var role model.Role
	if err := m.db.Preload("Permissions").Where("name = ?", name).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("get role: %w", err)
	}
	return &role, nil
}

// GetRoleByID retrieves a role by its ID with permissions preloaded.
func (m *Manager) GetRoleByID(id uint64) (*model.Role, error) {
	var role model.Role
	if err := m.db.Preload("Permissions").First(&role, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("get role: %w", err)
	}
	return &role, nil
}

// ListRoles retrieves all roles.
func (m *Manager) ListRoles() ([]model.Role, error) {
	var roles []model.Role
	if err := m.db.Preload("Permissions").Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	return roles, nil
}

// UpdateRole updates a role's information.
func (m *Manager) UpdateRole(id uint64, displayName, description string) (*model.Role, error) {
	role, err := m.GetRoleByID(id)
	if err != nil {
		return nil, err
	}

	updates := map[string]interface{}{}
	if displayName != "" {
		updates["display_name"] = displayName
	}
	if description != "" {
		updates["description"] = description
	}

	if err := m.db.Model(role).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("update role: %w", err)
	}

	return role, nil
}

// DeleteRole removes a role by ID. System roles cannot be deleted.
func (m *Manager) DeleteRole(id uint64) error {
	role, err := m.GetRoleByID(id)
	if err != nil {
		return err
	}

	if role.IsSystem {
		return ErrCannotDeleteSystemRole
	}

	if err := m.db.Delete(role).Error; err != nil {
		return fmt.Errorf("delete role: %w", err)
	}

	return nil
}

// AssignPermissionToRole adds a permission to a role.
func (m *Manager) AssignPermissionToRole(roleID, permissionID uint64) error {
	role, err := m.GetRoleByID(roleID)
	if err != nil {
		return err
	}

	var perm model.Permission
	if err := m.db.First(&perm, permissionID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrPermissionNotFound
		}
		return fmt.Errorf("get permission: %w", err)
	}

	if err := m.db.Model(role).Association("Permissions").Append(&perm); err != nil {
		return fmt.Errorf("assign permission to role: %w", err)
	}

	return nil
}

// RemovePermissionFromRole removes a permission from a role.
func (m *Manager) RemovePermissionFromRole(roleID, permissionID uint64) error {
	role, err := m.GetRoleByID(roleID)
	if err != nil {
		return err
	}

	var perm model.Permission
	if err := m.db.First(&perm, permissionID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrPermissionNotFound
		}
		return fmt.Errorf("get permission: %w", err)
	}

	if err := m.db.Model(role).Association("Permissions").Delete(&perm); err != nil {
		return fmt.Errorf("remove permission from role: %w", err)
	}

	return nil
}

// AssignRoleToUser assigns a role to a user.
func (m *Manager) AssignRoleToUser(userID, roleID, grantedBy uint64) error {
	// Check if role exists
	if _, err := m.GetRoleByID(roleID); err != nil {
		return err
	}

	// Check if user exists
	var user model.User
	if err := m.db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("user not found")
		}
		return fmt.Errorf("get user: %w", err)
	}

	// Check if user already has this role
	var existing model.UserRole
	err := m.db.Where("user_id = ? AND role_id = ?", userID, roleID).First(&existing).Error
	if err == nil {
		return ErrUserAlreadyHasRole
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("check existing role: %w", err)
	}

	userRole := &model.UserRole{
		UserID:    userID,
		RoleID:    roleID,
		GrantedBy: grantedBy,
	}

	if err := m.db.Create(userRole).Error; err != nil {
		return fmt.Errorf("assign role to user: %w", err)
	}

	return nil
}

// RemoveRoleFromUser removes a role from a user.
func (m *Manager) RemoveRoleFromUser(userID, roleID uint64) error {
	result := m.db.Where("user_id = ? AND role_id = ?", userID, roleID).Delete(&model.UserRole{})
	if result.Error != nil {
		return fmt.Errorf("remove role from user: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("user role assignment not found")
	}
	return nil
}

// GetUserRoles retrieves all roles assigned to a user.
func (m *Manager) GetUserRoles(userID uint64) ([]model.Role, error) {
	var roles []model.Role
	err := m.db.
		Joins("JOIN user_roles ON user_roles.role_id = roles.id").
		Where("user_roles.user_id = ?", userID).
		Preload("Permissions").
		Find(&roles).Error

	if err != nil {
		return nil, fmt.Errorf("get user roles: %w", err)
	}

	return roles, nil
}

// GetUserPermissions retrieves all permissions for a user across all their roles.
func (m *Manager) GetUserPermissions(userID uint64) ([]model.Permission, error) {
	var perms []model.Permission
	err := m.db.
		Distinct().
		Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
		Joins("JOIN user_roles ON user_roles.role_id = role_permissions.role_id").
		Where("user_roles.user_id = ?", userID).
		Find(&perms).Error

	if err != nil {
		return nil, fmt.Errorf("get user permissions: %w", err)
	}

	return perms, nil
}

// HasPermission checks if a user has a specific permission.
func (m *Manager) HasPermission(userID uint64, permissionName string) (bool, error) {
	var count int64
	err := m.db.Model(&model.Permission{}).
		Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
		Joins("JOIN user_roles ON user_roles.role_id = role_permissions.role_id").
		Where("user_roles.user_id = ? AND permissions.name = ?", userID, permissionName).
		Count(&count).Error

	if err != nil {
		return false, fmt.Errorf("check permission: %w", err)
	}

	return count > 0, nil
}

// HasRole checks if a user has a specific role.
func (m *Manager) HasRole(userID uint64, roleName string) (bool, error) {
	var count int64
	err := m.db.Model(&model.UserRole{}).
		Joins("JOIN roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id = ? AND roles.name = ?", userID, roleName).
		Count(&count).Error

	if err != nil {
		return false, fmt.Errorf("check role: %w", err)
	}

	return count > 0, nil
}

// HasAnyRole checks if a user has any of the specified roles.
func (m *Manager) HasAnyRole(userID uint64, roleNames []string) (bool, error) {
	var count int64
	err := m.db.Model(&model.UserRole{}).
		Joins("JOIN roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id = ? AND roles.name IN ?", userID, roleNames).
		Count(&count).Error

	if err != nil {
		return false, fmt.Errorf("check roles: %w", err)
	}

	return count > 0, nil
}

// HasAllRoles checks if a user has all of the specified roles.
func (m *Manager) HasAllRoles(userID uint64, roleNames []string) (bool, error) {
	var count int64
	err := m.db.Model(&model.UserRole{}).
		Joins("JOIN roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id = ? AND roles.name IN ?", userID, roleNames).
		Count(&count).Error

	if err != nil {
		return false, fmt.Errorf("check roles: %w", err)
	}

	return count == int64(len(roleNames)), nil
}

// RequirePermission checks if a user has a permission, returns error if not.
func (m *Manager) RequirePermission(userID uint64, permissionName string) error {
	has, err := m.HasPermission(userID, permissionName)
	if err != nil {
		return err
	}
	if !has {
		return ErrPermissionDenied
	}
	return nil
}

// RequireRole checks if a user has a role, returns error if not.
func (m *Manager) RequireRole(userID uint64, roleName string) error {
	has, err := m.HasRole(userID, roleName)
	if err != nil {
		return err
	}
	if !has {
		return ErrPermissionDenied
	}
	return nil
}

// RequireAnyRole checks if a user has any of the specified roles, returns error if not.
func (m *Manager) RequireAnyRole(userID uint64, roleNames []string) error {
	has, err := m.HasAnyRole(userID, roleNames)
	if err != nil {
		return err
	}
	if !has {
		return ErrPermissionDenied
	}
	return nil
}

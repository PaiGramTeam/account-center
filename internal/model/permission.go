package model

import (
	"time"

	"gorm.io/gorm"
)

// Permission represents a specific action that can be performed in the system.
type Permission struct {
	ID          uint64         `gorm:"primaryKey" json:"id"`
	Name        string         `gorm:"size:100;uniqueIndex;not null" json:"name"`
	Resource    string         `gorm:"size:100;not null;index" json:"resource"`
	Action      string         `gorm:"size:50;not null;index" json:"action"`
	Description string         `gorm:"size:512" json:"description"`
	CreatedAt   time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP(3)" json:"created_at"`
	UpdatedAt   time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP(3)" json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`

	Roles []Role `gorm:"many2many:role_permissions;" json:"-"`
}

// Role represents a collection of permissions assigned to users.
type Role struct {
	ID          uint64         `gorm:"primaryKey" json:"id"`
	Name        string         `gorm:"size:100;uniqueIndex;not null" json:"name"`
	DisplayName string         `gorm:"size:255;not null" json:"display_name"`
	Description string         `gorm:"size:512" json:"description"`
	IsSystem    bool           `gorm:"default:false;not null;index" json:"is_system"`
	CreatedAt   time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP(3)" json:"created_at"`
	UpdatedAt   time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP(3)" json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`

	Permissions []Permission `gorm:"many2many:role_permissions;" json:"permissions,omitempty"`
	Users       []User       `gorm:"many2many:user_roles;" json:"-"`
}

// UserRole represents the assignment of roles to users.
type UserRole struct {
	ID        uint64    `gorm:"primaryKey" json:"id"`
	UserID    uint64    `gorm:"index:idx_user_role,priority:1;not null" json:"user_id"`
	RoleID    uint64    `gorm:"index:idx_user_role,priority:2;not null" json:"role_id"`
	GrantedBy uint64    `gorm:"index" json:"granted_by"`
	CreatedAt time.Time `gorm:"not null;default:CURRENT_TIMESTAMP(3)" json:"created_at"`
	UpdatedAt time.Time `gorm:"not null;default:CURRENT_TIMESTAMP(3)" json:"updated_at"`

	User User `gorm:"foreignKey:UserID" json:"-"`
	Role Role `gorm:"foreignKey:RoleID" json:"-"`
}

// RolePermission represents the assignment of permissions to roles.
type RolePermission struct {
	RoleID       uint64    `gorm:"primaryKey;index:idx_role_permission,priority:1;not null"`
	PermissionID uint64    `gorm:"primaryKey;index:idx_role_permission,priority:2;not null"`
	CreatedAt    time.Time `gorm:"not null;default:CURRENT_TIMESTAMP(3)"`

	Role       Role       `gorm:"foreignKey:RoleID"`
	Permission Permission `gorm:"foreignKey:PermissionID"`
}

// TableName specifies the table name for UserRole.
func (UserRole) TableName() string {
	return "user_roles"
}

// TableName specifies the table name for RolePermission.
func (RolePermission) TableName() string {
	return "role_permissions"
}

// Predefined system roles
const (
	RoleAdmin     = "admin"
	RoleModerator = "moderator"
	RoleUser      = "user"
	RoleGuest     = "guest"
)

// Predefined permission resources
const (
	ResourceUser       = "user"
	ResourceRole       = "role"
	ResourcePermission = "permission"
	ResourceBot        = "bot"
	ResourceSession    = "session"
	ResourceAudit      = "audit"
)

// Predefined permission actions
const (
	ActionCreate = "create"
	ActionRead   = "read"
	ActionUpdate = "update"
	ActionDelete = "delete"
	ActionList   = "list"
	ActionManage = "manage"
)

// BuildPermissionName constructs a standard permission name from resource and action.
func BuildPermissionName(resource, action string) string {
	return resource + ":" + action
}

// Predefined permission constants
const (
	// User permissions
	PermUserRead   = "user:read"
	PermUserWrite  = "user:write"
	PermUserDelete = "user:delete"
	PermUserManage = "user:manage"

	// Role permissions
	PermRoleRead   = "role:read"
	PermRoleWrite  = "role:write"
	PermRoleDelete = "role:delete"
	PermRoleManage = "role:manage"

	// Permission management
	PermPermissionRead   = "permission:read"
	PermPermissionWrite  = "permission:write"
	PermPermissionDelete = "permission:delete"
	PermPermissionManage = "permission:manage"

	// Bot permissions
	PermBotRead   = "bot:read"
	PermBotWrite  = "bot:write"
	PermBotDelete = "bot:delete"
	PermBotManage = "bot:manage"

	// Audit permissions
	PermAuditRead = "audit:read"
)

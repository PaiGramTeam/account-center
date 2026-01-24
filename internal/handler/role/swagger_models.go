//go:generate swagger generate spec -o ../../../docs/swagger.json --scan-models

package role

import (
	"time"
)

// RoleResponse represents a role with its associated permissions count
// swagger:model roleResponse
type RoleResponse struct {
	// Role ID
	// example: 1
	ID uint64 `json:"id"`
	// Role name (unique identifier)
	// example: admin
	Name string `json:"name"`
	// Display name for UI
	// example: Administrator
	DisplayName string `json:"display_name"`
	// Role description
	// example: Full system access
	Description string `json:"description"`
	// Number of permissions assigned to this role
	// example: 25
	PermissionCount int `json:"permission_count"`
	// Number of users with this role
	// example: 3
	UserCount int `json:"user_count"`
	// Creation timestamp
	// example: 2024-01-20T10:00:00Z
	CreatedAt time.Time `json:"created_at"`
	// Last update timestamp
	// example: 2024-01-20T10:00:00Z
	UpdatedAt time.Time `json:"updated_at"`
}

// RoleListItem represents a role item in list responses
// swagger:model roleListItem
type RoleListItem struct {
	// Role ID
	// example: 1
	ID uint64 `json:"id"`
	// Role name
	// example: admin
	Name string `json:"name"`
	// Display name
	// example: Administrator
	DisplayName string `json:"display_name"`
	// Description
	// example: Full system access
	Description string `json:"description"`
	// Permission count
	// example: 25
	PermissionCount int `json:"permission_count"`
	// User count
	// example: 3
	UserCount int `json:"user_count"`
	// Created at
	// example: 2024-01-20T10:00:00Z
	CreatedAt time.Time `json:"created_at"`
}

// RoleDetailResponse represents detailed role information
// swagger:model roleDetailResponse
type RoleDetailResponse struct {
	// Response data
	Data RoleResponse `json:"data"`
}

// swagger:response roleDetailResponse
type swaggerRoleDetailResponse struct {
	// in: body
	Body RoleDetailResponse
}

// swagger:parameters listRoles
type listRolesParams struct {
	// Page number (starting from 1)
	// in: query
	// minimum: 1
	// default: 1
	// example: 1
	Page int `json:"page"`
	// Number of items per page
	// in: query
	// minimum: 1
	// maximum: 100
	// default: 20
	// example: 20
	PageSize int `json:"page_size"`
}

// swagger:parameters getRole updateRole deleteRole assignPermissionToRole
type roleIDParam struct {
	// Role ID
	// in: path
	// required: true
	// example: 1
	ID uint64 `json:"id"`
}

// swagger:parameters removePermissionFromRole
type rolePermissionParams struct {
	// Role ID
	// in: path
	// required: true
	// example: 1
	ID uint64 `json:"id"`
	// Permission ID
	// in: path
	// required: true
	// example: 5
	PermissionID uint64 `json:"permissionId"`
}

// swagger:parameters createRole
type createRoleParams struct {
	// Role creation request
	// in: body
	// required: true
	Body CreateRoleRequest
}

// swagger:model createRoleRequest
type swaggerCreateRoleRequest struct {
	// Role name (must be unique)
	// required: true
	// example: moderator
	Name string `json:"name"`
	// Display name
	// required: true
	// example: Moderator
	DisplayName string `json:"display_name"`
	// Description
	// example: Can moderate content
	Description string `json:"description"`
}

// swagger:parameters updateRole
type updateRoleParams struct {
	// Role ID
	// in: path
	// required: true
	// example: 1
	ID uint64 `json:"id"`
	// Role update request
	// in: body
	// required: true
	Body UpdateRoleRequest
}

// swagger:model updateRoleRequest
type swaggerUpdateRoleRequest struct {
	// Display name
	// example: Senior Moderator
	DisplayName string `json:"display_name"`
	// Description
	// example: Can moderate content and manage junior moderators
	Description string `json:"description"`
}

// swagger:parameters assignPermissionToRole
type assignPermissionParams struct {
	// Role ID
	// in: path
	// required: true
	// example: 1
	ID uint64 `json:"id"`
	// Permission assignment request
	// in: body
	// required: true
	Body AssignPermissionRequest
}

// swagger:model assignPermissionRequest
type swaggerAssignPermissionRequest struct {
	// Permission ID to assign
	// required: true
	// example: 10
	PermissionID uint64 `json:"permission_id"`
}

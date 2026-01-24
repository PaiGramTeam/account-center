//go:generate swagger generate spec -o ../../../docs/swagger.json --scan-models

package permission

import (
	"time"
)

// PermissionResponse represents a permission
// swagger:model permissionResponse
type PermissionResponse struct {
	// Permission ID
	// example: 1
	ID uint64 `json:"id"`
	// Permission name (unique identifier)
	// example: user.read
	Name string `json:"name"`
	// Display name for UI
	// example: Read Users
	DisplayName string `json:"display_name"`
	// Permission description
	// example: Allows reading user information
	Description string `json:"description"`
	// Permission category
	// example: user_management
	Category string `json:"category"`
	// Creation timestamp
	// example: 2024-01-20T10:00:00Z
	CreatedAt time.Time `json:"created_at"`
	// Last update timestamp
	// example: 2024-01-20T10:00:00Z
	UpdatedAt time.Time `json:"updated_at"`
}

// PermissionListItem represents a permission item in list responses
// swagger:model permissionListItem
type PermissionListItem struct {
	// Permission ID
	// example: 1
	ID uint64 `json:"id"`
	// Permission name
	// example: user.read
	Name string `json:"name"`
	// Display name
	// example: Read Users
	DisplayName string `json:"display_name"`
	// Description
	// example: Allows reading user information
	Description string `json:"description"`
	// Category
	// example: user_management
	Category string `json:"category"`
}

// PermissionDetailResponse represents detailed permission information
// swagger:model permissionDetailResponse
type PermissionDetailResponse struct {
	// Response data
	Data PermissionResponse `json:"data"`
}

// swagger:response permissionDetailResponse
type swaggerPermissionDetailResponse struct {
	// in: body
	Body PermissionDetailResponse
}

// swagger:parameters listPermissions
type listPermissionsParams struct {
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
	// Filter by category
	// in: query
	// example: user_management
	Category string `json:"category"`
}

// swagger:parameters getPermission updatePermission deletePermission
type permissionIDParam struct {
	// Permission ID
	// in: path
	// required: true
	// example: 1
	ID uint64 `json:"id"`
}

// swagger:parameters createPermission
type createPermissionParams struct {
	// Permission creation request
	// in: body
	// required: true
	Body CreatePermissionRequest
}

// swagger:model createPermissionRequest
type swaggerCreatePermissionRequest struct {
	// Permission name (must be unique)
	// required: true
	// example: content.moderate
	Name string `json:"name"`
	// Resource name
	// required: true
	// example: content
	Resource string `json:"resource"`
	// Action name
	// required: true
	// example: moderate
	Action string `json:"action"`
	// Description
	// example: Allows moderating user-generated content
	Description string `json:"description"`
}

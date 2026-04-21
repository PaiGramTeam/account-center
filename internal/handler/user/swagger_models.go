//go:generate swagger generate spec -o ../../docs/swagger.json --scan-models

package user

import (
	"time"

	"paigram/internal/model"
	serviceme "paigram/internal/service/me"
)

// ErrorResponse represents a standard error payload for handlers.
//
// swagger:model errorResponse
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail contains structured error information
type ErrorDetail struct {
	// Error code for client-side handling and internationalization
	// example: INVALID_CREDENTIALS
	Code string `json:"code"`
	// User-friendly error message
	// example: Invalid email or password
	Message string `json:"message"`
	// Optional additional error details
	// example: {"field": "email", "reason": "Email not verified"}
	Details interface{} `json:"details,omitempty"`
}

// swagger:response errorResponse
type swaggerErrorResponse struct {
	// in: body
	Body ErrorResponse
}

// swagger:model userEmail
type UserEmailPayload struct {
	Email      string     `json:"email"`
	IsPrimary  bool       `json:"is_primary"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
}

// swagger:model userListItem
type UserListItem struct {
	ID               uint64           `json:"id"`
	Status           model.UserStatus `json:"status"`
	PrimaryLoginType model.LoginType  `json:"primary_login_type"`
	DisplayName      string           `json:"display_name"`
	AvatarURL        string           `json:"avatar_url,omitempty"`
	Roles            []string         `json:"roles,omitempty"`
	LastLoginAt      *time.Time       `json:"last_login_at,omitempty"`
	CreatedAt        time.Time        `json:"created_at"`
}

// swagger:parameters listUsers
type listUsersParams struct {
	// Page number (starting from 1)
	// in: query
	// example: 1
	Page int `json:"page"`
	// Number of items per page
	// in: query
	// default: 20
	// maximum: 100
	// example: 20
	PageSize int `json:"page_size"`
	// Sort field (created_at, last_login_at, id)
	// in: query
	// example: created_at
	SortBy string `json:"sort_by"`
	// Sort order (asc, desc)
	// in: query
	// example: desc
	Order string `json:"order"`
	// Filter by user status
	// in: query
	// example: active
	Status string `json:"status"`
	// Search by email or display name
	// in: query
	// example: john
	Search string `json:"search"`
}

// swagger:model pagination
type Pagination struct {
	// Total number of records
	// example: 150
	Total int64 `json:"total"`
	// Current page number
	// example: 1
	Page int `json:"page"`
	// Number of items per page
	// example: 20
	PageSize int `json:"page_size"`
	// Total number of pages
	// example: 8
	TotalPages int `json:"total_pages"`
}

// swagger:model userListResponse
type UserListResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Items      []UserListItem `json:"items"`
		Pagination Pagination     `json:"pagination"`
	} `json:"data"`
}

// swagger:response userListResponse
type swaggerUserListResponse struct {
	// in: body
	Body UserListResponse
}

// swagger:model userDetail
type UserDetail struct {
	ID                 uint64             `json:"id"`
	Status             model.UserStatus   `json:"status"`
	PrimaryLoginType   model.LoginType    `json:"primary_login_type"`
	DisplayName        string             `json:"display_name"`
	AvatarURL          string             `json:"avatar_url,omitempty"`
	Bio                string             `json:"bio,omitempty"`
	Locale             string             `json:"locale,omitempty"`
	PrimaryEmail       string             `json:"primary_email"`
	Emails             []UserEmailPayload `json:"emails"`
	Roles              []string           `json:"roles,omitempty"`
	Permissions        []string           `json:"permissions,omitempty"`
	TwoFactorEnabled   bool               `json:"two_factor_enabled"`
	ActiveSessionCount int64              `json:"active_session_count"`
	LastLoginAt        *time.Time         `json:"last_login_at,omitempty"`
	CreatedAt          time.Time          `json:"created_at"`
	UpdatedAt          time.Time          `json:"updated_at"`
}

// swagger:model userDetailResponse
type UserDetailResponse struct {
	Code    int        `json:"code"`
	Message string     `json:"message"`
	Data    UserDetail `json:"data"`
}

// swagger:response userDetailResponse
type swaggerUserDetailResponse struct {
	// in: body
	Body UserDetailResponse
}

// swagger:model userMessageOnly
type UserMessageOnly struct {
	Message string `json:"message"`
}

// swagger:response userMessageResponse
type swaggerUserMessageResponse struct {
	// in: body
	Body struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    UserMessageOnly `json:"data"`
	}
}

// swagger:response userLoginMethodsResponse
type swaggerUserLoginMethodsResponse struct {
	// in: body
	Body struct {
		Code    int                         `json:"code"`
		Message string                      `json:"message"`
		Data    []serviceme.LoginMethodView `json:"data"`
	}
}

// swagger:parameters getUser
type getUserParams struct {
	// User ID.
	// in: path
	// required: true
	ID uint64 `json:"id"`
}

// swagger:parameters listUserLoginMethods
type listUserLoginMethodsParams struct {
	// User ID.
	// in: path
	// required: true
	ID uint64 `json:"id"`
}

// swagger:parameters patchUserPrimaryLoginMethod
type patchUserPrimaryLoginMethodParams struct {
	// User ID.
	// in: path
	// required: true
	ID uint64 `json:"id"`
	// Provider key.
	// in: path
	// required: true
	// example: github
	Provider string `json:"provider,omitempty"`
}

// swagger:parameters createUser
type createUserParams struct {
	// User creation details
	// in: body
	// required: true
	Body CreateUserRequest
}

// swagger:model createUserRequest
type CreateUserRequest struct {
	// User email address
	// required: true
	// example: user@example.com
	Email string `json:"email"`
	// User display name
	// required: true
	// example: John Doe
	DisplayName string `json:"display_name"`
	// User password (8-72 characters)
	// required: true
	// example: SecurePassword123
	Password string `json:"password"`
	// User roles
	// example: ["user"]
	Roles []string `json:"roles,omitempty"`
	// User status
	// example: active
	Status string `json:"status,omitempty"`
	// User locale
	// example: en_US
	Locale string `json:"locale,omitempty"`
}

// swagger:model createUserResponse
type CreateUserResponse struct {
	Code    int        `json:"code"`
	Message string     `json:"message"`
	Data    UserDetail `json:"data"`
}

// swagger:response createUserResponse
type swaggerCreateUserResponse struct {
	// in: body
	Body CreateUserResponse
}

// swagger:parameters updateUser
type updateUserParams struct {
	// User ID
	// in: path
	// required: true
	ID uint64 `json:"id"`
	// User update details
	// in: body
	// required: true
	Body UpdateUserRequest
}

// swagger:model updateUserRequest
type UpdateUserRequest struct {
	// User display name
	// example: John Doe
	DisplayName string `json:"display_name,omitempty"`
	// User status
	// example: suspended
	Status string `json:"status,omitempty"`
	// User roles
	// example: ["user", "moderator"]
	Roles []string `json:"roles,omitempty"`
	// User locale
	// example: en_US
	Locale string `json:"locale,omitempty"`
}

// swagger:model updateUserResponse
type UpdateUserResponse struct {
	Code    int        `json:"code"`
	Message string     `json:"message"`
	Data    UserDetail `json:"data"`
}

// swagger:response updateUserResponse
type swaggerUpdateUserResponse struct {
	// in: body
	Body UpdateUserResponse
}

// swagger:parameters deleteUser
type deleteUserParams struct {
	// User ID
	// in: path
	// required: true
	ID uint64 `json:"id"`
	// Hard delete (permanently remove from database)
	// in: query
	// example: false
	HardDelete bool `json:"hard_delete"`
}

// swagger:model deleteUserResponse
type DeleteUserResponse struct {
	Data struct {
		// Success message
		// example: user deleted successfully
		Message string `json:"message"`
	} `json:"data"`
}

// swagger:response deleteUserResponse
type swaggerDeleteUserResponse struct {
	// in: body
	Body DeleteUserResponse
}

// swagger:parameters updateUserStatus
type updateUserStatusParams struct {
	// User ID
	// in: path
	// required: true
	ID uint64 `json:"id"`
	// Status update details
	// in: body
	// required: true
	Body UpdateUserStatusRequest
}

// swagger:model updateUserStatusRequest
type UpdateUserStatusRequest struct {
	// User status (active, pending, suspended, deleted)
	// required: true
	// example: suspended
	Status string `json:"status"`
}

// swagger:model updateUserStatusResponse
type UpdateUserStatusResponse struct {
	Data struct {
		// Success message
		// example: user status updated successfully
		Message string `json:"message"`
		// Updated status
		// example: suspended
		Status string `json:"status"`
	} `json:"data"`
}

// swagger:response updateUserStatusResponse
type swaggerUpdateUserStatusResponse struct {
	// in: body
	Body UpdateUserStatusResponse
}

// swagger:parameters resetUserPassword
type resetUserPasswordParams struct {
	// User ID
	// in: path
	// required: true
	ID uint64 `json:"id"`
	// Password reset details
	// in: body
	// required: true
	Body ResetPasswordRequest
}

// swagger:model resetPasswordRequest
type ResetPasswordRequest struct {
	// New password (8-72 characters)
	// required: true
	// example: NewSecurePassword123
	NewPassword string `json:"new_password"`
	// Whether to invalidate all user sessions
	// example: true
	InvalidateSessions bool `json:"invalidate_sessions,omitempty"`
}

// swagger:model resetPasswordResponse
type ResetPasswordResponse struct {
	Data struct {
		// Success message
		// example: password reset successfully
		Message string `json:"message"`
	} `json:"data"`
}

// swagger:response resetPasswordResponse
type swaggerResetPasswordResponse struct {
	// in: body
	Body ResetPasswordResponse
}

// swagger:parameters getAuditLogs
type getAuditLogsParams struct {
	// User ID
	// in: path
	// required: true
	ID uint64 `json:"id"`
	// Page int `json:"page"`
	// Number of items per page
	// in: query
	// default: 20
	// maximum: 100
	// example: 20
	PageSize int `json:"page_size"`
	// Filter by action type
	// in: query
	// example: profile_update
	ActionType string `json:"action_type"`
}

// swagger:model auditLogItem
type AuditLogItem struct {
	// Log ID
	// example: 1
	ID uint64 `json:"id"`
	// User ID
	// example: 12345
	UserID uint64 `json:"user_id"`
	// Action type
	// example: profile_update
	Action string `json:"action"`
	// Action details
	// example: {"field": "display_name", "old_value": "Old Name", "new_value": "New Name"}
	Details interface{} `json:"details"`
	// IP address
	// example: 192.168.1.100
	IP string `json:"ip"`
	// Created timestamp
	// example: 2024-01-23T10:00:00Z
	CreatedAt time.Time `json:"created_at"`
}

// swagger:model auditLogsResponse
type AuditLogsResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Items      []AuditLogItem `json:"items"`
		Pagination Pagination     `json:"pagination"`
	} `json:"data"`
}

// swagger:response auditLogsResponse
type swaggerAuditLogsResponse struct {
	// in: body
	Body AuditLogsResponse
}

// swagger:parameters getUserRoles
type getUserRolesParams struct {
	// User ID
	// in: path
	// required: true
	ID uint64 `json:"id"`
	// Page number (starting from 1)
	// in: query
	// example: 1
	Page int `json:"page"`
	// Number of items per page
	// in: query
	// example: 20
	PageSize int `json:"page_size"`
}

// swagger:model userRoleItem
type UserRoleItem struct {
	// Role ID
	// example: 1
	ID uint64 `json:"id"`
	// Role name
	// example: admin
	Name string `json:"name"`
	// Role display name
	// example: Administrator
	DisplayName string `json:"display_name"`
	// Role description
	// example: System administrator with full access
	Description string `json:"description"`
	// Whether this is a system role
	// example: true
	IsSystem bool `json:"is_system"`
	// When the role was assigned
	// example: 2024-01-23T10:00:00Z
	AssignedAt time.Time `json:"assigned_at"`
	// User ID who granted this role
	// example: 1
	GrantedBy uint64 `json:"granted_by"`
}

// swagger:model userRolesResponse
type UserRolesResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Items      []UserRoleItem `json:"items"`
		Pagination Pagination     `json:"pagination"`
	} `json:"data"`
}

// swagger:response userRolesResponse
type swaggerUserRolesResponse struct {
	// in: body
	Body UserRolesResponse
}

// swagger:parameters getUserPermissions
type getUserPermissionsParams struct {
	// User ID
	// in: path
	// required: true
	ID uint64 `json:"id"`
	// Page number (starting from 1)
	// in: query
	// example: 1
	Page int `json:"page"`
	// Number of items per page
	// in: query
	// example: 50
	PageSize int `json:"page_size"`
}

// swagger:model userPermissionItem
type UserPermissionItem struct {
	// Permission ID
	// example: 1
	ID uint64 `json:"id"`
	// Permission name
	// example: users:read
	Name string `json:"name"`
	// Resource name
	// example: users
	Resource string `json:"resource"`
	// Action name
	// example: read
	Action string `json:"action"`
	// Permission description
	// example: View user information
	Description string `json:"description"`
	// Roles that grant this permission
	// example: ["admin", "moderator"]
	InheritedFrom []string `json:"inherited_from"`
}

// swagger:model userPermissionsMeta
type UserPermissionsMeta struct {
	// User's assigned roles
	// example: ["admin", "moderator"]
	Roles []string `json:"roles"`
}

// swagger:model userPermissionsData
type UserPermissionsData struct {
	Items      []UserPermissionItem `json:"items"`
	Pagination Pagination           `json:"pagination"`
	Meta       UserPermissionsMeta  `json:"meta"`
}

// swagger:model userPermissionsResponse
type UserPermissionsResponse struct {
	Code    int                 `json:"code"`
	Message string              `json:"message"`
	Data    UserPermissionsData `json:"data"`
}

// swagger:response userPermissionsResponse
type swaggerUserPermissionsResponse struct {
	// in: body
	Body UserPermissionsResponse
}

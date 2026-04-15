//go:generate swagger generate spec -o ../../../docs/swagger.json --scan-models

package authority

// swagger:model authorityPermissionInfo
type swaggerAuthorityPermissionInfo struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

// swagger:model authorityRoleItem
type swaggerAuthorityRoleItem struct {
	ID          uint                             `json:"id"`
	Name        string                           `json:"name"`
	Description string                           `json:"description"`
	IsSystem    bool                             `json:"is_system"`
	CreatedAt   string                           `json:"created_at"`
	UpdatedAt   string                           `json:"updated_at"`
	Permissions []swaggerAuthorityPermissionInfo `json:"permissions"`
}

// swagger:model authorityListResponse
type swaggerAuthorityListResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Total int                        `json:"total"`
		Page  int                        `json:"page"`
		Data  []swaggerAuthorityRoleItem `json:"data"`
	} `json:"data"`
}

// swagger:response authorityListResponse
type swaggerAuthorityListResponseWrapper struct {
	// in: body
	Body swaggerAuthorityListResponse
}

// swagger:response authorityDetailResponse
type swaggerAuthorityDetailResponseWrapper struct {
	// in: body
	Body struct {
		Code    int                      `json:"code"`
		Message string                   `json:"message"`
		Data    swaggerAuthorityRoleItem `json:"data"`
	}
}

// swagger:response authorityPermissionsResponse
type swaggerAuthorityPermissionsResponseWrapper struct {
	// in: body
	Body struct {
		Code    int                              `json:"code"`
		Message string                           `json:"message"`
		Data    []swaggerAuthorityPermissionInfo `json:"data"`
	}
}

// swagger:model authorityUserItem
type swaggerAuthorityUserItem struct {
	ID           uint64 `json:"id"`
	DisplayName  string `json:"display_name"`
	PrimaryEmail string `json:"primary_email"`
	AssignedAt   string `json:"assigned_at"`
	GrantedBy    uint64 `json:"granted_by"`
}

// swagger:response authorityUsersResponse
type swaggerAuthorityUsersResponseWrapper struct {
	// in: body
	Body struct {
		Code    int                        `json:"code"`
		Message string                     `json:"message"`
		Data    []swaggerAuthorityUserItem `json:"data"`
	}
}

// swagger:parameters listAuthorities
type listAuthoritiesParams struct {
	// Page number
	// in: query
	Page int `json:"page"`
	// Page size
	// in: query
	PageSize int `json:"page_size"`
	// Name filter
	// in: query
	Name string `json:"name"`
}

// swagger:parameters getAuthority updateAuthority deleteAuthority assignPermissions getRolePermissions getAuthorityUsers replaceAuthorityUsers
type authorityIDParam struct {
	// Authority ID
	// in: path
	// required: true
	ID uint64 `json:"id"`
}

// swagger:parameters createAuthority
type createAuthorityParams struct {
	// in: body
	// required: true
	Body swaggerCreateAuthorityRequest
}

// swagger:model createAuthorityRequest
type swaggerCreateAuthorityRequest struct {
	// required: true
	Name          string `json:"name"`
	Description   string `json:"description"`
	PermissionIDs []uint `json:"permission_ids"`
}

// swagger:parameters updateAuthority
type updateAuthorityParams struct {
	// Authority ID
	// in: path
	// required: true
	ID uint64 `json:"id"`
	// in: body
	// required: true
	Body swaggerUpdateAuthorityRequest
}

// swagger:model updateAuthorityRequest
type swaggerUpdateAuthorityRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

// swagger:parameters assignPermissions
type assignPermissionsParams struct {
	// Authority ID
	// in: path
	// required: true
	ID uint64 `json:"id"`
	// in: body
	// required: true
	Body swaggerAssignPermissionsRequest
}

// swagger:model assignPermissionsRequest
type swaggerAssignPermissionsRequest struct {
	// required: true
	PermissionIDs []uint `json:"permission_ids"`
}

// swagger:parameters replaceAuthorityUsers
type replaceAuthorityUsersParams struct {
	// Authority ID
	// in: path
	// required: true
	ID uint64 `json:"id"`
	// in: body
	// required: true
	Body swaggerReplaceAuthorityUsersRequest
}

// swagger:model replaceAuthorityUsersRequest
type swaggerReplaceAuthorityUsersRequest struct {
	// required: true
	UserIDs []uint64 `json:"user_ids"`
}

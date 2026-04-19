package authority

import (
	"time"

	"paigram/internal/response"
	serviceauthority "paigram/internal/service/authority"
)

// CreateAuthorityRequest 创建角色请求
type CreateAuthorityRequest struct {
	Name          string `json:"name" binding:"required,min=2,max=50"`
	Description   string `json:"description" binding:"max=200"`
	PermissionIDs []uint `json:"permission_ids"`
}

// UpdateAuthorityRequest 更新角色请求
type UpdateAuthorityRequest struct {
	Name        *string `json:"name" binding:"omitempty,min=2,max=50"`
	Description *string `json:"description" binding:"omitempty,max=200"`
}

// AssignPermissionsRequest 分配权限请求
type AssignPermissionsRequest struct {
	PermissionIDs []uint `json:"permission_ids" binding:"required"`
}

// ReplaceAuthorityUsersRequest 全量替换角色下的用户请求
type ReplaceAuthorityUsersRequest struct {
	UserIDs []uint64 `json:"user_ids"`
}

// ListAuthoritiesResponse 角色列表响应
type ListAuthoritiesResponse struct {
	Items      []serviceauthority.RoleWithPermissions `json:"items"`
	Pagination *response.PaginationMeta               `json:"pagination"`
}

// AuthorityUserItem 角色下的用户信息
type AuthorityUserItem struct {
	ID           uint64    `json:"id"`
	DisplayName  string    `json:"display_name"`
	PrimaryEmail string    `json:"primary_email"`
	AssignedAt   time.Time `json:"assigned_at"`
	GrantedBy    uint64    `json:"granted_by"`
}

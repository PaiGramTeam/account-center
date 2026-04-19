package authority

import "time"

// CreateAuthorityParams 创建角色参数
type CreateAuthorityParams struct {
	Name          string
	Description   string
	PermissionIDs []uint
}

// UpdateAuthorityParams 更新角色参数
type UpdateAuthorityParams struct {
	Name        *string
	Description *string
}

// ListAuthoritiesParams 角色列表查询参数
type ListAuthoritiesParams struct {
	Page     int
	PageSize int
	Name     string // 模糊搜索
}

// ListAuthoritiesResult 角色列表查询结果
type ListAuthoritiesResult struct {
	Total    int                   `json:"total"`
	Page     int                   `json:"page"`
	PageSize int                   `json:"page_size"`
	Data     []RoleWithPermissions `json:"data"`
}

// RoleWithPermissions 角色及其权限
type RoleWithPermissions struct {
	ID          uint             `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	IsSystem    bool             `json:"is_system"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
	Permissions []PermissionInfo `json:"permissions"`
}

// PermissionInfo 权限信息
type PermissionInfo struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

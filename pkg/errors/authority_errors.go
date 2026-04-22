package errors

import "errors"

const (
	ErrorCodeAdminRequired               = "ADMIN_REQUIRED"
	ErrorCodeConsumerGrantRequired       = "CONSUMER_GRANT_REQUIRED"
	ErrorCodePlatformAccountAlreadyBound = "PLATFORM_ACCOUNT_ALREADY_BOUND"
	ErrorCodePlatformBindingNotFound     = "PLATFORM_BINDING_NOT_FOUND"
	ErrorCodePlatformServiceUnavailable  = "PLATFORM_SERVICE_UNAVAILABLE"
	ErrorCodePrimaryProfileInvalid       = "PRIMARY_PROFILE_INVALID"
)

var (
	// 角色相关错误
	ErrRoleNotFound      = errors.New("角色不存在")
	ErrRoleNameDuplicate = errors.New("角色名称已存在")
	ErrSystemRoleProtect = errors.New("系统角色不可删除")
	ErrRoleInUse         = errors.New("角色正在使用中,无法删除")

	// 权限相关错误
	ErrPermissionDenied  = errors.New("权限不足")
	ErrInvalidPermission = errors.New("无效的权限")

	// Casbin相关错误
	ErrCasbinEnforce       = errors.New("Casbin鉴权失败")
	ErrCasbinPolicyInvalid = errors.New("无效的Casbin策略")
)

package authority

import (
	"errors"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"paigram/internal/middleware"
	"paigram/internal/response"
	"paigram/internal/service/authority"
	pkgerrors "paigram/pkg/errors"
)

type AuthorityHandler struct {
	service *authority.AuthorityService
}

func NewAuthorityHandler(service *authority.AuthorityService) *AuthorityHandler {
	return &AuthorityHandler{service: service}
}

// CreateAuthority 创建角色
// @Tags      Authority
// @Summary   创建角色
// @Security  BearerAuth
// @Accept    json
// @Produce   json
// @Param     data  body      CreateAuthorityRequest  true  "角色信息"
// @Success   200   {object}  response.Response{data=model.Role}
// @Failure   400   {object}  response.Response
// @Failure   401   {object}  response.Response
// @Failure   403   {object}  response.Response
// @Failure   409   {object}  response.Response
// @Failure   500   {object}  response.Response
// @Router    /api/v1/authorities [post]
func (h *AuthorityHandler) CreateAuthority(c *gin.Context) {
	var req CreateAuthorityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	role, err := h.service.CreateAuthority(authority.CreateAuthorityParams{
		Name:          req.Name,
		Description:   req.Description,
		PermissionIDs: req.PermissionIDs,
	})
	if err != nil {
		// 区分不同类型的错误,返回正确的 HTTP 状态码
		if errors.Is(err, pkgerrors.ErrRoleNameDuplicate) {
			response.Conflict(c, "角色名称已存在")
			return
		}
		response.InternalServerError(c, "创建角色失败: "+err.Error())
		return
	}

	response.Success(c, role)
}

// GetAuthority 获取角色详情
// @Tags      Authority
// @Summary   获取角色详情
// @Security  BearerAuth
// @Produce   json
// @Param     id   path      int  true  "角色ID"
// @Success   200  {object}  response.Response{data=model.Role}
// @Failure   400  {object}  response.Response
// @Failure   401  {object}  response.Response
// @Failure   403  {object}  response.Response
// @Failure   404  {object}  response.Response
// @Failure   500  {object}  response.Response
// @Router    /api/v1/authorities/{id} [get]
func (h *AuthorityHandler) GetAuthority(c *gin.Context) {
	roleID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.BadRequest(c, "无效的角色ID")
		return
	}

	role, err := h.service.GetAuthority(uint(roleID))
	if err != nil {
		// 区分不同类型的错误
		if errors.Is(err, pkgerrors.ErrRoleNotFound) {
			response.NotFound(c, "角色不存在")
			return
		}
		response.InternalServerError(c, "获取角色失败: "+err.Error())
		return
	}

	response.Success(c, role)
}

// ListAuthorities 获取角色列表
// @Tags      Authority
// @Summary   获取角色列表（分页）
// @Security  BearerAuth
// @Produce   json
// @Param     page      query     int     false  "页码"  default(1)
// @Param     page_size query     int     false  "每页数量"  default(10)
// @Param     name      query     string  false  "角色名称（模糊搜索）"
// @Success   200       {object}  response.Response{data=ListAuthoritiesResponse}
// @Failure   401       {object}  response.Response
// @Failure   403       {object}  response.Response
// @Failure   500       {object}  response.Response
// @Router    /api/v1/authorities [get]
func (h *AuthorityHandler) ListAuthorities(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	name := c.Query("name")

	// 验证分页参数
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}

	result, err := h.service.ListAuthorities(authority.ListAuthoritiesParams{
		Page:     page,
		PageSize: pageSize,
		Name:     name,
	})
	if err != nil {
		response.InternalServerError(c, "获取角色列表失败: "+err.Error())
		return
	}

	response.Success(c, result)
}

// UpdateAuthority 更新角色
// @Tags      Authority
// @Summary   更新角色信息
// @Security  BearerAuth
// @Accept    json
// @Produce   json
// @Param     id    path      int                    true  "角色ID"
// @Param     data  body      UpdateAuthorityRequest true  "更新信息"
// @Success   200   {object}  response.Response
// @Failure   400   {object}  response.Response
// @Failure   401   {object}  response.Response
// @Failure   403   {object}  response.Response
// @Failure   404   {object}  response.Response
// @Failure   409   {object}  response.Response
// @Failure   500   {object}  response.Response
// @Router    /api/v1/authorities/{id} [put]
func (h *AuthorityHandler) UpdateAuthority(c *gin.Context) {
	roleID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.BadRequest(c, "无效的角色ID")
		return
	}

	var req UpdateAuthorityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	if req.Name != nil && strings.TrimSpace(*req.Name) == "" {
		response.BadRequest(c, "参数错误: name不能为空")
		return
	}

	err = h.service.UpdateAuthority(uint(roleID), authority.UpdateAuthorityParams{
		Name:        req.Name,
		Description: req.Description,
	})
	if err != nil {
		// 区分不同类型的错误
		if errors.Is(err, pkgerrors.ErrRoleNotFound) {
			response.NotFound(c, "角色不存在")
			return
		}
		if errors.Is(err, pkgerrors.ErrRoleNameDuplicate) {
			response.Conflict(c, "角色名称已存在")
			return
		}
		if errors.Is(err, pkgerrors.ErrSystemRoleProtect) {
			response.Forbidden(c, "系统角色不可修改")
			return
		}
		response.InternalServerError(c, "更新角色失败: "+err.Error())
		return
	}

	response.SuccessWithMessage(c, nil, "更新成功")
}

// DeleteAuthority 删除角色
// @Tags      Authority
// @Summary   删除角色
// @Security  BearerAuth
// @Produce   json
// @Param     id   path      int  true  "角色ID"
// @Success   200  {object}  response.Response
// @Failure   400  {object}  response.Response
// @Failure   401  {object}  response.Response
// @Failure   403  {object}  response.Response  "系统角色不可删除"
// @Failure   404  {object}  response.Response
// @Failure   409  {object}  response.Response
// @Failure   500  {object}  response.Response
// @Router    /api/v1/authorities/{id} [delete]
func (h *AuthorityHandler) DeleteAuthority(c *gin.Context) {
	roleID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.BadRequest(c, "无效的角色ID")
		return
	}

	err = h.service.DeleteAuthority(uint(roleID))
	if err != nil {
		// 区分不同类型的错误
		if errors.Is(err, pkgerrors.ErrRoleNotFound) {
			response.NotFound(c, "角色不存在")
			return
		}
		if errors.Is(err, pkgerrors.ErrSystemRoleProtect) {
			response.Forbidden(c, "系统角色不可删除")
			return
		}
		if errors.Is(err, pkgerrors.ErrRoleInUse) {
			response.Conflict(c, "角色正在使用中,无法删除")
			return
		}
		response.InternalServerError(c, "删除角色失败: "+err.Error())
		return
	}

	response.SuccessWithMessage(c, nil, "删除成功")
}

// AssignPermissions 为角色分配权限
// @Tags      Authority
// @Summary   为角色分配权限（全量覆盖）
// @Security  BearerAuth
// @Accept    json
// @Produce   json
// @Param     id    path      int                       true  "角色ID"
// @Param     data  body      AssignPermissionsRequest  true  "权限ID列表"
// @Success   200   {object}  response.Response
// @Failure   400   {object}  response.Response
// @Failure   401   {object}  response.Response
// @Failure   403   {object}  response.Response
// @Failure   404   {object}  response.Response
// @Failure   500   {object}  response.Response
// @Router    /api/v1/authorities/{id}/permissions [post]
func (h *AuthorityHandler) AssignPermissions(c *gin.Context) {
	roleID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.BadRequest(c, "无效的角色ID")
		return
	}

	var req AssignPermissionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "参数错误: "+err.Error())
		return
	}

	err = h.service.AssignPermissions(uint(roleID), req.PermissionIDs)
	if err != nil {
		if errors.Is(err, pkgerrors.ErrRoleNotFound) {
			response.NotFound(c, "角色不存在")
			return
		}
		response.InternalServerError(c, "分配权限失败: "+err.Error())
		return
	}

	response.SuccessWithMessage(c, nil, "分配成功")
}

// GetRolePermissions 获取角色的权限列表
// @Tags      Authority
// @Summary   获取角色的所有权限
// @Security  BearerAuth
// @Produce   json
// @Param     id   path      int  true  "角色ID"
// @Success   200  {object}  response.Response{data=[]model.Permission}
// @Failure   400  {object}  response.Response
// @Failure   401  {object}  response.Response
// @Failure   403  {object}  response.Response
// @Failure   404  {object}  response.Response
// @Failure   500  {object}  response.Response
// @Router    /api/v1/authorities/{id}/permissions [get]
func (h *AuthorityHandler) GetRolePermissions(c *gin.Context) {
	roleID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.BadRequest(c, "无效的角色ID")
		return
	}

	permissions, err := h.service.GetRolePermissions(uint(roleID))
	if err != nil {
		if errors.Is(err, pkgerrors.ErrRoleNotFound) {
			response.NotFound(c, "角色不存在")
			return
		}
		response.InternalServerError(c, "获取权限失败: "+err.Error())
		return
	}

	response.Success(c, permissions)
}

// GetAuthorityUsers 获取角色下的用户列表
// @Tags      Authority
// @Summary   获取角色下的用户列表
// @Security  BearerAuth
// @Produce   json
// @Param     id   path      int  true  "角色ID"
// @Success   200  {object}  response.Response{data=[]AuthorityUserItem}
// @Failure   400  {object}  response.Response
// @Failure   401  {object}  response.Response
// @Failure   403  {object}  response.Response
// @Failure   404  {object}  response.Response
// @Failure   500  {object}  response.Response
// @Router    /api/v1/authorities/{id}/users [get]
func (h *AuthorityHandler) GetAuthorityUsers(c *gin.Context) {
	roleID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.BadRequest(c, "无效的角色ID")
		return
	}

	users, err := h.service.GetAuthorityUsers(uint(roleID))
	if err != nil {
		if errors.Is(err, pkgerrors.ErrRoleNotFound) {
			response.NotFound(c, "角色不存在")
			return
		}
		response.InternalServerError(c, "获取角色用户失败: "+err.Error())
		return
	}

	items := make([]AuthorityUserItem, 0, len(users))
	for _, user := range users {
		items = append(items, AuthorityUserItem{
			ID:           user.ID,
			DisplayName:  user.DisplayName,
			PrimaryEmail: user.PrimaryEmail,
			AssignedAt:   user.AssignedAt,
			GrantedBy:    user.GrantedBy,
		})
	}

	response.Success(c, items)
}

// ReplaceAuthorityUsers 全量替换角色下的用户列表
// @Tags      Authority
// @Summary   全量替换角色下的用户列表
// @Security  BearerAuth
// @Accept    json
// @Produce   json
// @Param     id    path      int                         true  "角色ID"
// @Param     data  body      ReplaceAuthorityUsersRequest true  "用户ID列表"
// @Success   200   {object}  response.Response
// @Failure   400   {object}  response.Response
// @Failure   401   {object}  response.Response
// @Failure   403   {object}  response.Response
// @Failure   404   {object}  response.Response
// @Failure   500   {object}  response.Response
// @Router    /api/v1/authorities/{id}/users [put]
func (h *AuthorityHandler) ReplaceAuthorityUsers(c *gin.Context) {
	roleID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.BadRequest(c, "无效的角色ID")
		return
	}

	var req ReplaceAuthorityUsersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	if req.UserIDs == nil {
		response.BadRequest(c, "参数错误: user_ids is required")
		return
	}

	currentUserID, exists := middleware.GetUserID(c)
	if !exists {
		response.UnauthorizedWithCode(c, "UNAUTHORIZED", "authentication required", nil)
		return
	}

	err = h.service.ReplaceAuthorityUsers(uint(roleID), req.UserIDs, currentUserID)
	if err != nil {
		if errors.Is(err, pkgerrors.ErrRoleNotFound) {
			response.NotFound(c, "角色不存在")
			return
		}
		if errors.Is(err, pkgerrors.ErrSystemRoleProtect) {
			response.Forbidden(c, "系统角色至少需要保留一名成员")
			return
		}
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFound(c, "用户不存在")
			return
		}
		response.InternalServerError(c, "更新角色用户失败: "+err.Error())
		return
	}

	response.SuccessWithMessage(c, nil, "更新成功")
}

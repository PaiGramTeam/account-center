package casbin

import (
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"paigram/internal/logging"
	"paigram/internal/response"
	servicecasbin "paigram/internal/service/casbin"
	pkgerrors "paigram/pkg/errors"
)

type CasbinHandler struct {
	service *servicecasbin.CasbinService
}

func NewCasbinHandler(service *servicecasbin.CasbinService) *CasbinHandler {
	return &CasbinHandler{service: service}
}

// ReplaceAuthorityPolicies replaces all API policies for an authority.
// @Tags      Casbin
// @Summary   Replace authority API policies
// @Security  BearerAuth
// @Accept    json
// @Produce   json
// @Param     id    path      int                             true  "Authority ID"
// @Param     data  body      ReplaceAuthorityPoliciesRequest true  "Authority API policy list"
// @Success   200   {object}  response.Response
// @Failure   400   {object}  response.Response
// @Failure   401   {object}  response.Response
// @Failure   403   {object}  response.Response
// @Failure   404   {object}  response.Response
// @Failure   500   {object}  response.Response
func (h *CasbinHandler) ReplaceAuthorityPolicies(c *gin.Context) {
	roleID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.BadRequest(c, "无效的角色ID")
		return
	}

	var req ReplaceAuthorityPoliciesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logging.Error("replace authority policies: invalid request body", zap.Error(err), zap.Uint64("role_id", roleID))
		response.BadRequest(c, "参数错误")
		return
	}

	policies := make([]servicecasbin.CasbinPolicyInfo, len(req.Policies))
	for i, policy := range req.Policies {
		policies[i] = servicecasbin.CasbinPolicyInfo{
			Path:   policy.Path,
			Method: policy.Method,
		}
	}

	if err := h.service.ReplaceAuthorityPolicies(uint(roleID), policies); err != nil {
		if errors.Is(err, pkgerrors.ErrRoleNotFound) {
			response.NotFound(c, "角色不存在")
			return
		}
		logging.Error("replace authority policies failed", zap.Error(err), zap.Uint64("role_id", roleID))
		response.InternalServerError(c, "更新API权限失败")
		return
	}

	response.SuccessWithMessage(c, nil, "更新成功")
}

// GetAuthorityPolicies returns all API policies for an authority.
// @Tags      Casbin
// @Summary   Get authority API policies
// @Security  BearerAuth
// @Produce   json
// @Param     id   path      int  true  "Authority ID"
// @Success   200  {object}  response.Response{data=GetAuthorityPoliciesResponse}
// @Failure   400  {object}  response.Response
// @Failure   401  {object}  response.Response
// @Failure   403  {object}  response.Response
// @Failure   404  {object}  response.Response
// @Failure   500  {object}  response.Response
func (h *CasbinHandler) GetAuthorityPolicies(c *gin.Context) {
	roleID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		response.BadRequest(c, "无效的角色ID")
		return
	}

	policies, err := h.service.GetAuthorityPolicies(uint(roleID))
	if err != nil {
		if errors.Is(err, pkgerrors.ErrRoleNotFound) {
			response.NotFound(c, "角色不存在")
			return
		}
		logging.Error("get authority policies failed", zap.Error(err), zap.Uint64("role_id", roleID))
		response.InternalServerError(c, "获取API权限失败")
		return
	}

	responsePolicies := make([]AuthorityPolicyRequest, len(policies))
	for i, policy := range policies {
		responsePolicies[i] = AuthorityPolicyRequest{
			Path:   policy.Path,
			Method: policy.Method,
		}
	}

	response.Success(c, GetAuthorityPoliciesResponse{
		RoleID:   uint(roleID),
		Policies: responsePolicies,
	})
}

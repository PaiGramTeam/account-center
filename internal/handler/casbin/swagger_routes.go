package casbin

// swagger:route PUT /api/v1/casbin/authorities/{id}/policies casbin replaceAuthorityPolicies
// 替换角色的 API 策略集合。
//
// Responses:
//   200: standardResponse
//   400: errorResponse
//   401: errorResponse
//   403: errorResponse
//   404: errorResponse
//   500: errorResponse

// swagger:route GET /api/v1/casbin/authorities/{id}/policies casbin getAuthorityPolicies
// 获取角色的 API 策略集合。
//
// Responses:
//   200: authorityPoliciesResponse
//   400: errorResponse
//   401: errorResponse
//   403: errorResponse
//   404: errorResponse
//   500: errorResponse

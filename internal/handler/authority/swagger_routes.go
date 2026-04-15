package authority

// swagger:route POST /api/v1/authorities authorities createAuthority
// 创建角色。
//
// Responses:
//   200: standardResponse
//   400: errorResponse
//   401: errorResponse
//   403: errorResponse
//   409: errorResponse
//   500: errorResponse

// swagger:route GET /api/v1/authorities authorities listAuthorities
// 获取角色列表。
//
// Responses:
//   200: authorityListResponse
//   401: errorResponse
//   403: errorResponse
//   500: errorResponse

// swagger:route GET /api/v1/authorities/{id} authorities getAuthority
// 获取角色详情。
//
// Responses:
//   200: authorityDetailResponse
//   400: errorResponse
//   401: errorResponse
//   403: errorResponse
//   404: errorResponse
//   500: errorResponse

// swagger:route PUT /api/v1/authorities/{id} authorities updateAuthority
// 更新角色。
//
// Responses:
//   200: standardResponse
//   400: errorResponse
//   401: errorResponse
//   403: errorResponse
//   404: errorResponse
//   409: errorResponse
//   500: errorResponse

// swagger:route DELETE /api/v1/authorities/{id} authorities deleteAuthority
// 删除角色。
//
// Responses:
//   200: standardResponse
//   400: errorResponse
//   401: errorResponse
//   403: errorResponse
//   404: errorResponse
//   409: errorResponse
//   500: errorResponse

// swagger:route POST /api/v1/authorities/{id}/permissions authorities assignPermissions
// 为角色分配权限。
//
// Responses:
//   200: standardResponse
//   400: errorResponse
//   401: errorResponse
//   403: errorResponse
//   404: errorResponse
//   500: errorResponse

// swagger:route GET /api/v1/authorities/{id}/permissions authorities getRolePermissions
// 获取角色权限列表。
//
// Responses:
//   200: authorityPermissionsResponse
//   400: errorResponse
//   401: errorResponse
//   403: errorResponse
//   404: errorResponse
//   500: errorResponse

// swagger:route GET /api/v1/authorities/{id}/users authorities getAuthorityUsers
// 获取角色下的用户列表。
//
// Responses:
//   200: authorityUsersResponse
//   400: errorResponse
//   401: errorResponse
//   403: errorResponse
//   404: errorResponse
//   500: errorResponse

// swagger:route PUT /api/v1/authorities/{id}/users authorities replaceAuthorityUsers
// 全量替换角色下的用户列表。
//
// Responses:
//   200: standardResponse
//   400: errorResponse
//   401: errorResponse
//   403: errorResponse
//   404: errorResponse
//   500: errorResponse

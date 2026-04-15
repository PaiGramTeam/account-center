//go:generate swagger generate spec -o ../../../docs/swagger.json --scan-models

package casbin

// swagger:model authorityPolicyRequest
type swaggerAuthorityPolicyRequest struct {
	// required: true
	Path string `json:"path"`
	// required: true
	Method string `json:"method"`
}

// swagger:model authorityPoliciesResponse
type swaggerAuthorityPoliciesResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		RoleID   uint                            `json:"role_id"`
		Policies []swaggerAuthorityPolicyRequest `json:"policies"`
	} `json:"data"`
}

// swagger:response authorityPoliciesResponse
type swaggerAuthorityPoliciesResponseWrapper struct {
	// in: body
	Body swaggerAuthorityPoliciesResponse
}

// swagger:parameters getAuthorityPolicies replaceAuthorityPolicies
type authorityPoliciesIDParam struct {
	// Authority ID
	// in: path
	// required: true
	ID uint64 `json:"id"`
}

// swagger:parameters replaceAuthorityPolicies
type replaceAuthorityPoliciesParams struct {
	// Authority ID
	// in: path
	// required: true
	ID uint64 `json:"id"`
	// in: body
	// required: true
	Body swaggerReplaceAuthorityPoliciesRequest
}

// swagger:model replaceAuthorityPoliciesRequest
type swaggerReplaceAuthorityPoliciesRequest struct {
	// required: true
	Policies []swaggerAuthorityPolicyRequest `json:"policies"`
}

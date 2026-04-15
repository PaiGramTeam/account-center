package casbin

// ReplaceAuthorityPoliciesRequest replaces an authority's API policies.
type ReplaceAuthorityPoliciesRequest struct {
	Policies []AuthorityPolicyRequest `json:"policies" binding:"required,dive"`
}

// AuthorityPolicyRequest is one API policy entry.
type AuthorityPolicyRequest struct {
	Path   string `json:"path" binding:"required"`
	Method string `json:"method" binding:"required,oneof=GET POST PUT PATCH DELETE"`
}

// GetAuthorityPoliciesResponse returns the policies assigned to an authority.
type GetAuthorityPoliciesResponse struct {
	RoleID   uint                     `json:"role_id"`
	Policies []AuthorityPolicyRequest `json:"policies"`
}

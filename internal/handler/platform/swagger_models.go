package platform

// swagger:model platformListItem
type swaggerPlatformListItem struct {
	Platform         string   `json:"platform"`
	DisplayName      string   `json:"display_name"`
	SupportedActions []string `json:"supported_actions"`
}

// swagger:model platformListResponse
type swaggerPlatformListResponse struct {
	Code    int                       `json:"code"`
	Message string                    `json:"message"`
	Data    []swaggerPlatformListItem `json:"data"`
}

// swagger:response platformListResponse
type swaggerPlatformListResponseWrapper struct {
	// in: body
	Body swaggerPlatformListResponse
}

// swagger:model platformSchemaResponse
type swaggerPlatformSchemaResponse struct {
	Platform         string                 `json:"platform"`
	DisplayName      string                 `json:"display_name"`
	SupportedActions []string               `json:"supported_actions"`
	CredentialSchema map[string]interface{} `json:"credential_schema"`
}

// swagger:model platformSchemaEnvelope
type swaggerPlatformSchemaEnvelope struct {
	Code    int                           `json:"code"`
	Message string                        `json:"message"`
	Data    swaggerPlatformSchemaResponse `json:"data"`
}

// swagger:response platformSchemaEnvelope
type swaggerPlatformSchemaEnvelopeWrapper struct {
	// in: body
	Body swaggerPlatformSchemaEnvelope
}

// swagger:model platformErrorDetail
type swaggerPlatformErrorDetail struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

// swagger:model platformErrorResponse
type swaggerPlatformErrorResponse struct {
	Error swaggerPlatformErrorDetail `json:"error"`
}

// swagger:response platformErrorResponse
type swaggerPlatformErrorResponseWrapper struct {
	// in: body
	Body swaggerPlatformErrorResponse
}

// swagger:parameters getPlatformSchema
type swaggerPlatformSchemaParams struct {
	// Platform key
	// in: path
	// required: true
	// example: hoyoverse
	Platform string `json:"platform"`
}

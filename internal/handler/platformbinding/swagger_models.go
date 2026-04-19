package platformbinding

// swagger:model platformBindingItem
type swaggerPlatformBindingItem struct {
	ID                  uint64  `json:"id"`
	OwnerUserID         uint64  `json:"owner_user_id,omitempty"`
	Platform            string  `json:"platform"`
	ExternalAccountKey  *string `json:"external_account_key,omitempty"`
	PlatformServiceKey  string  `json:"platform_service_key"`
	DisplayName         string  `json:"display_name"`
	Status              string  `json:"status"`
	StatusReasonCode    *string `json:"status_reason_code,omitempty"`
	StatusReasonMessage *string `json:"status_reason_message,omitempty"`
	PrimaryProfileID    *int64  `json:"primary_profile_id,omitempty"`
	LastValidatedAt     *string `json:"last_validated_at,omitempty"`
	LastSyncedAt        *string `json:"last_synced_at,omitempty"`
	CreatedAt           string  `json:"created_at"`
	UpdatedAt           string  `json:"updated_at"`
}

// swagger:model platformBindingProfileItem
type swaggerPlatformBindingProfileItem struct {
	ID                 uint64  `json:"id"`
	BindingID          uint64  `json:"binding_id"`
	PlatformProfileKey string  `json:"platform_profile_key"`
	GameBiz            string  `json:"game_biz"`
	Region             string  `json:"region"`
	PlayerUID          string  `json:"player_uid"`
	Nickname           string  `json:"nickname"`
	Level              *int64  `json:"level,omitempty"`
	IsPrimary          bool    `json:"is_primary"`
	SourceUpdatedAt    *string `json:"source_updated_at,omitempty"`
	CreatedAt          string  `json:"created_at"`
	UpdatedAt          string  `json:"updated_at"`
}

// swagger:model platformBindingConsumerGrantItem
type swaggerPlatformBindingConsumerGrantItem struct {
	ID        uint64  `json:"id"`
	BindingID uint64  `json:"binding_id"`
	Consumer  string  `json:"consumer"`
	Status    string  `json:"status"`
	GrantedBy *int64  `json:"granted_by,omitempty"`
	GrantedAt string  `json:"granted_at"`
	RevokedAt *string `json:"revoked_at,omitempty"`
	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at"`
}

// swagger:model platformBindingListData
type swaggerPlatformBindingListData struct {
	Items []swaggerPlatformBindingItem `json:"items"`
}

// swagger:model platformBindingProfileListData
type swaggerPlatformBindingProfileListData struct {
	Items []swaggerPlatformBindingProfileItem `json:"items"`
}

// swagger:model platformBindingConsumerGrantListData
type swaggerPlatformBindingConsumerGrantListData struct {
	Items []swaggerPlatformBindingConsumerGrantItem `json:"items"`
}

// swagger:model platformBindingEnvelope
type swaggerPlatformBindingEnvelope struct {
	Code    int                        `json:"code"`
	Message string                     `json:"message"`
	Data    swaggerPlatformBindingItem `json:"data"`
}

// swagger:response platformBindingEnvelope
type swaggerPlatformBindingEnvelopeWrapper struct {
	// in: body
	Body swaggerPlatformBindingEnvelope
}

// swagger:model platformBindingListEnvelope
type swaggerPlatformBindingListEnvelope struct {
	Code    int                            `json:"code"`
	Message string                         `json:"message"`
	Data    swaggerPlatformBindingListData `json:"data"`
}

// swagger:response platformBindingListEnvelope
type swaggerPlatformBindingListEnvelopeWrapper struct {
	// in: body
	Body swaggerPlatformBindingListEnvelope
}

// swagger:model platformBindingProfileListEnvelope
type swaggerPlatformBindingProfileListEnvelope struct {
	Code    int                                   `json:"code"`
	Message string                                `json:"message"`
	Data    swaggerPlatformBindingProfileListData `json:"data"`
}

// swagger:response platformBindingProfileListEnvelope
type swaggerPlatformBindingProfileListEnvelopeWrapper struct {
	// in: body
	Body swaggerPlatformBindingProfileListEnvelope
}

// swagger:model platformBindingConsumerGrantListEnvelope
type swaggerPlatformBindingConsumerGrantListEnvelope struct {
	Code    int                                         `json:"code"`
	Message string                                      `json:"message"`
	Data    swaggerPlatformBindingConsumerGrantListData `json:"data"`
}

// swagger:response platformBindingConsumerGrantListEnvelope
type swaggerPlatformBindingConsumerGrantListEnvelopeWrapper struct {
	// in: body
	Body swaggerPlatformBindingConsumerGrantListEnvelope
}

// swagger:model platformBindingErrorDetail
type swaggerPlatformBindingErrorDetail struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

// swagger:model platformBindingErrorResponse
type swaggerPlatformBindingErrorResponse struct {
	Error swaggerPlatformBindingErrorDetail `json:"error"`
}

// swagger:response platformBindingErrorResponse
type swaggerPlatformBindingErrorResponseWrapper struct {
	// in: body
	Body swaggerPlatformBindingErrorResponse
}

// swagger:parameters createMyPlatformBinding
type swaggerCreatePlatformBindingParams struct {
	// in: body
	// required: true
	Body CreateBindingRequest
}

// swagger:parameters getMyPlatformBinding deleteMyPlatformBinding listMyPlatformBindingProfiles listMyPlatformBindingConsumerGrants putMyPlatformBindingConsumerGrant getPlatformBinding listPlatformBindingProfiles listPlatformBindingConsumerGrants putPlatformBindingConsumerGrant refreshPlatformBinding deletePlatformBinding
type swaggerPlatformBindingPathParams struct {
	// Binding ID.
	// in: path
	// required: true
	BindingID uint64 `json:"bindingId"`
}

// swagger:parameters putMyPlatformBindingConsumerGrant putPlatformBindingConsumerGrant
type swaggerPutPlatformBindingConsumerGrantParams struct {
	// Consumer name.
	// in: path
	// required: true
	Consumer string `json:"consumer"`

	// in: body
	// required: true
	Body PutConsumerGrantRequest
}

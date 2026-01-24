package profile

import "time"

// ErrorResponse represents a standard error payload.
//
// swagger:model profileErrorResponse
type ErrorResponse struct {
	// Description of the error.
	// example: profile not found
	Error string `json:"error"`
}

// swagger:response profileErrorResponse
type swaggerProfileErrorResponse struct {
	// in: body
	Body ErrorResponse
}

// swagger:parameters getProfile updateProfile
type swaggerProfileParams struct {
	// User ID
	// in: path
	// required: true
	// example: 12345
	ID uint64 `json:"id"`
}

// swagger:model profileResponse
type ProfileResponse struct {
	Data ProfileData `json:"data"`
}

// swagger:model profileData
type ProfileData struct {
	// User ID
	// example: 12345
	UserID uint64 `json:"user_id"`
	// Display name
	// example: John Doe
	DisplayName string `json:"display_name"`
	// Avatar URL
	// example: https://example.com/avatar.jpg
	AvatarURL string `json:"avatar_url,omitempty"`
	// User bio
	// example: Software developer from New York
	Bio string `json:"bio,omitempty"`
	// User locale
	// example: en_US
	Locale string `json:"locale"`
	// User status
	// example: active
	Status string `json:"status"`
	// Primary email address
	// example: user@example.com
	PrimaryEmail string `json:"primary_email"`
	// All email addresses
	Emails []EmailData `json:"emails"`
	// Last login timestamp
	// example: 2024-01-22T10:30:00Z
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	// Account creation timestamp
	// example: 2024-01-01T00:00:00Z
	CreatedAt time.Time `json:"created_at"`
	// Last update timestamp
	// example: 2024-01-22T10:30:00Z
	UpdatedAt time.Time `json:"updated_at"`
}

// swagger:model emailData
type EmailData struct {
	// Email address
	// example: user@example.com
	Email string `json:"email"`
	// Whether this is the primary email
	// example: true
	IsPrimary bool `json:"is_primary"`
	// Email verification timestamp
	// example: 2024-01-01T10:00:00Z
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
}

// swagger:response profileResponse
type swaggerProfileResponse struct {
	// in: body
	Body ProfileResponse
}

// swagger:parameters updateProfile
type swaggerUpdateProfileParams struct {
	// User ID
	// in: path
	// required: true
	// example: 12345
	ID uint64 `json:"id"`
	// Profile update details
	// in: body
	// required: true
	Body updateProfileRequest
}

// swagger:model updateProfileRequest
type UpdateProfileRequest struct {
	// New display name
	// example: Jane Doe
	DisplayName *string `json:"display_name,omitempty"`
	// New avatar URL
	// example: https://example.com/new-avatar.jpg
	AvatarURL *string `json:"avatar_url,omitempty"`
	// New bio
	// example: Full-stack developer
	Bio *string `json:"bio,omitempty"`
	// New locale
	// example: fr_FR
	Locale *string `json:"locale,omitempty"`
}

// swagger:model updateProfileResponse
type UpdateProfileResponse struct {
	Data UpdatedProfileData `json:"data"`
}

// swagger:model updatedProfileData
type UpdatedProfileData struct {
	// User ID
	// example: 12345
	UserID uint64 `json:"user_id"`
	// Updated display name
	// example: Jane Doe
	DisplayName string `json:"display_name"`
	// Updated avatar URL
	// example: https://example.com/new-avatar.jpg
	AvatarURL string `json:"avatar_url"`
	// Updated bio
	// example: Full-stack developer
	Bio string `json:"bio"`
	// Updated locale
	// example: fr_FR
	Locale string `json:"locale"`
}

// swagger:response updateProfileResponse
type swaggerUpdateProfileResponse struct {
	// in: body
	Body UpdateProfileResponse
}

// Account binding related models

// swagger:parameters getBoundAccounts bindAccount unbindAccount
type swaggerAccountParams struct {
	// User ID
	// in: path
	// required: true
	// example: 12345
	ID uint64 `json:"id"`
}

// swagger:parameters unbindAccount
type swaggerUnbindAccountParams struct {
	// User ID
	// in: path
	// required: true
	// example: 12345
	ID uint64 `json:"id"`
	// Provider name (telegram, google, github)
	// in: path
	// required: true
	// example: telegram
	Provider string `json:"provider"`
}

// swagger:model boundAccountData
type BoundAccountData struct {
	// Provider name
	// example: telegram
	Provider string `json:"provider"`
	// Provider account ID
	// example: 123456789
	ProviderAccountID string `json:"provider_account_id"`
	// Display name on the provider
	// example: John Doe
	DisplayName string `json:"display_name"`
	// Avatar URL from provider
	// example: https://t.me/i/userpic/320/username.jpg
	AvatarURL string `json:"avatar_url,omitempty"`
	// Binding timestamp
	// example: 2024-01-15T10:00:00Z
	BoundAt time.Time `json:"bound_at"`
	// Last used timestamp
	// example: 2024-01-23T10:00:00Z
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	// Whether this is the primary login method
	// example: false
	IsPrimary bool `json:"is_primary"`
}

// swagger:model boundAccountsResponse
type BoundAccountsResponse struct {
	Data []BoundAccountData `json:"data"`
}

// swagger:response boundAccountsResponse
type swaggerBoundAccountsResponse struct {
	// in: body
	Body BoundAccountsResponse
}

// swagger:parameters bindAccount
type swaggerBindAccountParams struct {
	// User ID
	// in: path
	// required: true
	// example: 12345
	ID uint64 `json:"id"`
	// Bind account request
	// in: body
	// required: true
	Body BindAccountRequest
}

// swagger:model bindAccountRequest
type BindAccountRequest struct {
	// Provider name (telegram, google, github)
	// required: true
	// example: telegram
	Provider string `json:"provider"`
	// Provider-specific authentication data
	// required: true
	ProviderData map[string]interface{} `json:"provider_data"`
}

// swagger:model bindAccountResponse
type BindAccountResponse struct {
	// Success message
	// example: account bound successfully
	Message string `json:"message"`
	// Binding details
	Data struct {
		// Provider name
		// example: telegram
		Provider string `json:"provider"`
		// Provider account ID
		// example: 123456789
		ProviderAccountID string `json:"provider_account_id"`
		// Binding timestamp
		// example: 2024-01-23T10:00:00Z
		BoundAt time.Time `json:"bound_at"`
	} `json:"data"`
}

// swagger:response bindAccountResponse
type swaggerBindAccountResponse struct {
	// in: body
	Body BindAccountResponse
}

// swagger:model unbindAccountResponse
type UnbindAccountResponse struct {
	// Success message
	// example: account unbound successfully
	Message string `json:"message"`
}

// swagger:response unbindAccountResponse
type swaggerUnbindAccountResponse struct {
	// in: body
	Body UnbindAccountResponse
}

// Email management related models

// swagger:parameters addEmail
type swaggerAddEmailParams struct {
	// User ID
	// in: path
	// required: true
	// example: 12345
	ID uint64 `json:"id"`
	// Add email request
	// in: body
	// required: true
	Body AddEmailRequest
}

// swagger:model addEmailRequest
type AddEmailRequest struct {
	// Email address to add
	// required: true
	// example: newemail@example.com
	Email string `json:"email"`
}

// swagger:model addEmailResponse
type AddEmailResponse struct {
	// Email address
	// example: newemail@example.com
	Email string `json:"email"`
	// Whether this is the primary email
	// example: false
	IsPrimary bool `json:"is_primary"`
	// Email verification timestamp (null if not verified)
	// example: null
	VerifiedAt *time.Time `json:"verified_at"`
	// Verification token (for development/testing)
	// example: base64-encoded-token
	VerificationToken string `json:"verification_token"`
	// Token expiry timestamp
	// example: 2024-01-24T10:00:00Z
	VerificationExpiresAt string `json:"verification_expires_at"`
	// Success message
	// example: email added successfully, verification email sent
	Message string `json:"message"`
}

// swagger:response addEmailResponse
type swaggerAddEmailResponse struct {
	// in: body
	Body AddEmailResponse
}

// swagger:parameters deleteEmail setPrimaryEmail resendVerificationEmail
type swaggerEmailOperationParams struct {
	// User ID
	// in: path
	// required: true
	// example: 12345
	ID uint64 `json:"id"`
	// Email address
	// in: path
	// required: true
	// example: user@example.com
	Email string `json:"email"`
}

// swagger:model deleteEmailResponse
type DeleteEmailResponse struct {
	// Success message
	// example: email deleted successfully
	Message string `json:"message"`
}

// swagger:response deleteEmailResponse
type swaggerDeleteEmailResponse struct {
	// in: body
	Body DeleteEmailResponse
}

// swagger:model setPrimaryEmailResponse
type SetPrimaryEmailResponse struct {
	// Success message
	// example: primary email updated successfully
	Message string `json:"message"`
}

// swagger:response setPrimaryEmailResponse
type swaggerSetPrimaryEmailResponse struct {
	// in: body
	Body SetPrimaryEmailResponse
}

// swagger:model resendVerificationResponse
type ResendVerificationResponse struct {
	// Success message
	// example: verification email sent successfully
	Message string `json:"message"`
	// Token expiry timestamp
	// example: 2024-01-24T10:00:00Z
	VerificationExpiresAt string `json:"verification_expires_at"`
}

// swagger:response resendVerificationResponse
type swaggerResendVerificationResponse struct {
	// in: body
	Body ResendVerificationResponse
}

package auth

// ErrorResponse represents a standard error payload.
//
// swagger:model authErrorResponse
type ErrorResponse struct {
	// Description of the error.
	// example: invalid credentials
	Error string `json:"error"`
}

// swagger:response authErrorResponse
type swaggerAuthErrorResponse struct {
	// in: body
	Body ErrorResponse
}

// swagger:parameters registerEmail
type swaggerRegisterEmailParams struct {
	// User registration details
	// in: body
	// required: true
	Body registerEmailRequest
}

// swagger:model registerEmailRequest
type RegisterEmailRequest struct {
	// User email address
	// required: true
	// example: user@example.com
	Email string `json:"email"`
	// User password (8-72 characters)
	// required: true
	// example: SecurePassword123
	Password string `json:"password"`
	// Display name for the user
	// required: true
	// example: John Doe
	DisplayName string `json:"display_name"`
	// User locale preference
	// example: en_US
	Locale string `json:"locale,omitempty"`
}

// swagger:model registerEmailResponse
type RegisterEmailResponse struct {
	Data struct {
		// New user ID
		// example: 12345
		UserID uint64 `json:"user_id"`
		// Email address
		// example: user@example.com
		Email string `json:"email"`
		// Email verification token
		// example: abcd1234efgh5678
		VerificationToken string `json:"verification_token"`
		// Verification token expiration
		// example: 2024-01-23T12:00:00Z
		VerificationExpiresAt string `json:"verification_expires_at"`
		// Whether email verification is required
		// example: true
		RequiresEmailVerification bool `json:"requires_email_verification"`
	} `json:"data"`
}

// swagger:response registerEmailResponse
type swaggerRegisterEmailResponse struct {
	// in: body
	Body RegisterEmailResponse
}

// swagger:parameters loginEmail
type swaggerLoginEmailParams struct {
	// Login credentials
	// in: body
	// required: true
	Body loginEmailRequest
}

// swagger:model loginEmailRequest
type LoginEmailRequest struct {
	// User email address
	// required: true
	// example: user@example.com
	Email string `json:"email"`
	// User password
	// required: true
	// example: SecurePassword123
	Password string `json:"password"`
}

// swagger:model loginResponse
type LoginResponse struct {
	Data struct {
		// User ID
		// example: 12345
		UserID uint64 `json:"user_id"`
		// JWT access token
		// example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
		AccessToken string `json:"access_token"`
		// JWT refresh token
		// example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
		RefreshToken string `json:"refresh_token"`
		// Access token expiration
		// example: 2024-01-23T12:15:00Z
		AccessExpiry string `json:"access_expiry"`
		// Refresh token expiration
		// example: 2024-01-30T12:00:00Z
		RefreshExpiry string `json:"refresh_expiry"`
	} `json:"data"`
}

// swagger:response loginResponse
type swaggerLoginResponse struct {
	// in: body
	Body LoginResponse
}

// swagger:parameters refreshToken
type swaggerRefreshTokenParams struct {
	// Refresh token details
	// in: body
	// required: true
	Body refreshTokenRequest
}

// swagger:model refreshTokenRequest
type RefreshTokenRequest struct {
	// JWT refresh token
	// required: true
	// example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
	RefreshToken string `json:"refresh_token"`
}

// swagger:parameters logout
type swaggerLogoutParams struct {
	// Token to revoke
	// in: body
	// required: true
	Body logoutRequest
}

// swagger:model logoutRequest
type LogoutRequest struct {
	// Access or refresh token to revoke
	// required: true
	// example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
	Token string `json:"token"`
}

// swagger:model logoutResponse
type LogoutResponse struct {
	Data struct {
		// Success message
		// example: logout successful
		Message string `json:"message"`
	} `json:"data"`
}

// swagger:response logoutResponse
type swaggerLogoutResponse struct {
	// in: body
	Body LogoutResponse
}

// swagger:parameters verifyEmail
type swaggerVerifyEmailParams struct {
	// Email verification details
	// in: body
	// required: true
	Body verifyEmailRequest
}

// swagger:model verifyEmailRequest
type VerifyEmailRequest struct {
	// Email address to verify
	// required: true
	// example: user@example.com
	Email string `json:"email"`
	// Verification token
	// required: true
	// example: abcd1234efgh5678
	Token string `json:"token"`
}

// swagger:model verifyEmailResponse
type VerifyEmailResponse struct {
	Data struct {
		// Success message
		// example: email verified
		Message string `json:"message"`
	} `json:"data"`
}

// swagger:response verifyEmailResponse
type swaggerVerifyEmailResponse struct {
	// in: body
	Body VerifyEmailResponse
}

// OAuth Models

// swagger:parameters initiateOAuth
type swaggerInitiateOAuthParams struct {
	// OAuth provider name (e.g., google, github)
	// in: path
	// required: true
	// example: google
	Provider string `json:"provider"`
	// OAuth initiation details
	// in: body
	Body initiateOAuthRequest
}

// swagger:model initiateOAuthRequest
type InitiateOAuthRequest struct {
	// Custom redirect URL after OAuth completion
	// example: https://myapp.com/auth/callback
	RedirectTo string `json:"redirect_to,omitempty"`
}

// swagger:model initiateOAuthResponse
type InitiateOAuthResponse struct {
	Data struct {
		// OAuth state token
		// example: random-state-token-123
		State string `json:"state"`
		// OAuth nonce token
		// example: random-nonce-token-456
		Nonce string `json:"nonce"`
		// State expiration time
		// example: 2024-01-23T12:05:00Z
		ExpiresAt string `json:"expires_at"`
		// OAuth provider authorization URL
		// example: https://accounts.google.com/o/oauth2/v2/auth?...
		AuthURL string `json:"auth_url"`
	} `json:"data"`
}

// swagger:response initiateOAuthResponse
type swaggerInitiateOAuthResponse struct {
	// in: body
	Body InitiateOAuthResponse
}

// swagger:parameters handleOAuthCallback
type swaggerOAuthCallbackParams struct {
	// OAuth provider name
	// in: path
	// required: true
	// example: google
	Provider string `json:"provider"`
	// OAuth callback data
	// in: body
	// required: true
	Body oauthCallbackRequest
}

// swagger:model oauthCallbackRequest
type OAuthCallbackRequest struct {
	// OAuth state token
	// required: true
	// example: random-state-token-123
	State string `json:"state"`
	// OAuth authorization code
	// example: auth-code-from-provider
	Code string `json:"code,omitempty"`
	// Provider account ID
	// required: true
	// example: 1234567890
	ProviderAccountID string `json:"provider_account_id"`
	// User email from provider
	// example: user@example.com
	Email string `json:"email,omitempty"`
	// Whether email is verified by provider
	// example: true
	EmailVerified bool `json:"email_verified,omitempty"`
	// User display name from provider
	// example: John Doe
	DisplayName string `json:"display_name,omitempty"`
	// User avatar URL from provider
	// example: https://example.com/avatar.jpg
	AvatarURL string `json:"avatar_url,omitempty"`
}

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
	// CAPTCHA token issued by Cloudflare Turnstile
	// example: 0.zrSnR7...
	CaptchaToken string `json:"captcha_token,omitempty"`
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
	// CAPTCHA token issued by Cloudflare Turnstile when risk checks require it
	// example: 0.zrSnR7...
	CaptchaToken string `json:"captcha_token,omitempty"`
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
		// OAuth provider authorization URL
		// example: https://accounts.google.com/o/oauth2/v2/auth?...
		AuthURL string `json:"auth_url"`
		// OAuth state token
		// example: random-state-token-123
		State string `json:"state"`
		// State expiration time
		// example: 2024-01-23T12:05:00Z
		ExpiresAt string `json:"expires_at"`
		// OAuth flow purpose
		// example: login
		Purpose string `json:"purpose"`
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
	// required: true
	// example: auth-code-from-provider
	Code string `json:"code"`
}

// swagger:model oauthCallbackResponse
type OAuthCallbackResponse struct {
	Data struct {
		// User ID. Returned for both login and bind callback success payloads.
		// example: 12345
		UserID uint64 `json:"user_id,omitempty"`
		// Login callback JWT access token.
		// example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
		AccessToken string `json:"access_token,omitempty"`
		// Login callback JWT refresh token.
		// example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
		RefreshToken string `json:"refresh_token,omitempty"`
		// Login callback access token expiration.
		// example: 2024-01-23T12:15:00Z
		AccessExpiry string `json:"access_expiry,omitempty"`
		// Login callback refresh token expiration.
		// example: 2024-01-30T12:00:00Z
		RefreshExpiry string `json:"refresh_expiry,omitempty"`
		// Login callback resolved email.
		// example: user@example.com
		Email string `json:"email,omitempty"`
		// Bind callback provider name.
		// example: github
		Provider string `json:"provider,omitempty"`
		// Bind callback provider account ID.
		// example: 1234567890
		ProviderAccountID string `json:"provider_account_id,omitempty"`
		// OAuth flow purpose.
		// example: bind_login_method
		Purpose string `json:"purpose,omitempty"`
		// Whether the login method is bound.
		// example: true
		Bound bool `json:"bound,omitempty"`
	} `json:"data"`
}

// swagger:response oauthCallbackResponse
type swaggerOAuthCallbackResponse struct {
	// in: body
	Body OAuthCallbackResponse
}

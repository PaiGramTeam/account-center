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

// Telegram Models

// swagger:parameters handleTelegramAuth
type swaggerTelegramAuthParams struct {
	// Telegram OAuth data
	// in: body
	// required: true
	Body TelegramAuthData
	// Telegram bot token for verification
	// in: header
	// required: true
	// example: 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
	BotToken string `json:"X-Telegram-Bot-Token"`
}

// swagger:model telegramAuthData
type TelegramAuthDataModel struct {
	// Telegram user ID
	// required: true
	// example: 123456789
	ID int64 `json:"id"`
	// User's first name
	// example: John
	FirstName string `json:"first_name"`
	// User's last name
	// example: Doe
	LastName string `json:"last_name,omitempty"`
	// Telegram username
	// example: johndoe
	Username string `json:"username,omitempty"`
	// User's photo URL
	// example: https://t.me/i/userpic/320/username.jpg
	PhotoURL string `json:"photo_url,omitempty"`
	// Unix timestamp when auth was performed
	// required: true
	// example: 1642345678
	AuthDate int64 `json:"auth_date"`
	// HMAC-SHA256 hash for data validation
	// required: true
	// example: f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3
	Hash string `json:"hash"`
}

// swagger:model telegramAuthResponse
type TelegramAuthResponse struct {
	// User information
	User struct {
		// User ID
		// example: 12345
		ID uint64 `json:"id"`
		// Account status
		// example: active
		Status string `json:"status"`
		// Display name
		// example: John Doe
		DisplayName string `json:"display_name"`
		// Primary email
		// example: johndoe@telegram.local
		Email string `json:"email"`
		// Avatar URL
		// example: https://t.me/i/userpic/320/username.jpg
		AvatarURL string `json:"avatar_url,omitempty"`
	} `json:"user"`
	// JWT access token
	// example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
	AccessToken string `json:"access_token"`
	// JWT refresh token
	// example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
	RefreshToken string `json:"refresh_token"`
	// Token type
	// example: Bearer
	TokenType string `json:"token_type"`
	// Access token expiration in seconds
	// example: 900
	ExpiresIn int `json:"expires_in"`
}

// swagger:response telegramAuthResponse
type swaggerTelegramAuthResponse struct {
	// in: body
	Body TelegramAuthResponse
}

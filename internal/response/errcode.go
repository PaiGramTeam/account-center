package response

// Error codes for standardized error handling across the API.
// Frontend can use these codes for internationalization and precise error handling.
const (
	// Authentication errors
	ErrCodeInvalidCredentials = "INVALID_CREDENTIALS"
	ErrCodeEmailNotVerified   = "EMAIL_NOT_VERIFIED"
	ErrCodeAccountSuspended   = "ACCOUNT_SUSPENDED"
	ErrCodeAccountPending     = "ACCOUNT_PENDING"
	ErrCodeInvalidToken       = "INVALID_TOKEN"
	ErrCodeTokenExpired       = "TOKEN_EXPIRED"
	ErrCodeTokenRevoked       = "TOKEN_REVOKED"
	ErrCodeUnauthorized       = "UNAUTHORIZED"
	ErrCodeForbidden          = "FORBIDDEN"

	// User management errors
	ErrCodeUserNotFound      = "USER_NOT_FOUND"
	ErrCodeUserAlreadyExists = "USER_ALREADY_EXISTS"
	ErrCodeEmailAlreadyInUse = "EMAIL_ALREADY_IN_USE"
	ErrCodeInvalidUserID     = "INVALID_USER_ID"
	ErrCodeInvalidUserStatus = "INVALID_USER_STATUS"
	ErrCodeCannotDeleteSelf  = "CANNOT_DELETE_SELF"

	// Validation errors
	ErrCodeInvalidInput       = "INVALID_INPUT"
	ErrCodeMissingField       = "MISSING_FIELD"
	ErrCodeInvalidEmail       = "INVALID_EMAIL"
	ErrCodeInvalidPassword    = "INVALID_PASSWORD"
	ErrCodePasswordTooWeak    = "PASSWORD_TOO_WEAK"
	ErrCodeInvalidDisplayName = "INVALID_DISPLAY_NAME"

	// Pagination errors
	ErrCodeInvalidPage      = "INVALID_PAGE"
	ErrCodeInvalidPageSize  = "INVALID_PAGE_SIZE"
	ErrCodeInvalidSortField = "INVALID_SORT_FIELD"

	// OAuth errors
	ErrCodeOAuthStateMismatch  = "OAUTH_STATE_MISMATCH"
	ErrCodeOAuthStateExpired   = "OAUTH_STATE_EXPIRED"
	ErrCodeOAuthProviderError  = "OAUTH_PROVIDER_ERROR"
	ErrCodeUnsupportedProvider = "UNSUPPORTED_PROVIDER"

	// Profile errors
	ErrCodeProfileNotFound    = "PROFILE_NOT_FOUND"
	ErrCodeInvalidProfileData = "INVALID_PROFILE_DATA"

	// Permission and role errors
	ErrCodeRoleNotFound      = "ROLE_NOT_FOUND"
	ErrCodePermissionDenied  = "PERMISSION_DENIED"
	ErrCodeInvalidRole       = "INVALID_ROLE"
	ErrCodeInvalidPermission = "INVALID_PERMISSION"

	// Internal errors
	ErrCodeInternalError = "INTERNAL_ERROR"
	ErrCodeDatabaseError = "DATABASE_ERROR"
	ErrCodeCacheError    = "CACHE_ERROR"
)

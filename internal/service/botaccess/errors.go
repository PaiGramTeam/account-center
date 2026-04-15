package botaccess

import "errors"

var (
	ErrBotIdentityNotFound             = errors.New("bot identity not found")
	ErrPlatformAccountOwnedByOtherUser = errors.New("platform account ref is owned by another user")
	ErrPlatformAccountMissing          = errors.New("platform account ref not found")
	ErrBotGrantNotFound                = errors.New("bot account grant not found")
	ErrBotGrantRevoked                 = errors.New("bot account grant revoked")
	ErrScopeNotGranted                 = errors.New("requested scope is not granted")
	ErrInvalidTicketConfig             = errors.New("invalid service ticket config")
	ErrInactiveAccountRef              = errors.New("platform account ref is not active")
)

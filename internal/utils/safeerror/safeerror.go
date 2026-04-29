// Package safeerror provides a small boundary helper for handler code that
// needs to surface error information to API clients without leaking internal
// implementation details (gorm/MySQL error strings, stack traces, etc.).
//
// The contract is intentionally narrow:
//
//   - Service-layer code that wants a SPECIFIC user-facing message returns an
//     *AppError. Handlers can extract that message safely with UserMessage.
//   - Every other error (wrapped MySQL/gorm errors, transport failures, etc.)
//     collapses to a generic "internal server error" string at the boundary,
//     so we never echo `Error 1062: Duplicate entry 'x' for key 'users.email'`
//     or similar database internals to a client.
//
// IMPORTANT: handlers MUST log the original err (with structured fields)
// separately. UserMessage is for the response body only; operators still need
// the real error chain for diagnosis.
package safeerror

import "errors"

// genericInternalErrorMessage is the user-facing fallback returned when the
// error chain does not contain a typed *AppError. It deliberately reveals
// nothing about the failure source.
const genericInternalErrorMessage = "internal server error"

// AppError is the canonical typed error a service-layer function may return
// when it wants the user-facing message to be specific (e.g., "user not
// found", "email already exists"). The Code field allows handlers to map to
// HTTP status without re-parsing the error text.
//
// AppError is NOT a replacement for sentinel errors like
// gorm.ErrRecordNotFound; handlers should still branch on those explicitly
// when nuanced status mapping is required. AppError is for the cases where
// the service author has consciously chosen a stable message + code pair.
type AppError struct {
	// Code is a short, stable identifier (e.g., "USER_NOT_FOUND",
	// "EMAIL_TAKEN") that clients/UI can branch on without parsing prose.
	Code string
	// Message is the user-safe, human-readable message. It MUST NOT contain
	// raw database error text, file paths, stack frames, or other internal
	// detail.
	Message string
	// Cause is the underlying error chain, preserved for logging and for
	// errors.Is / errors.As traversal. Cause is never exposed to clients.
	Cause error
}

// Error implements the error interface. It returns the user-safe Message so
// that a caller who accidentally wraps an *AppError with %v still emits only
// the safe text. The Cause is reachable via Unwrap.
func (e *AppError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// Unwrap exposes the underlying cause for errors.Is / errors.As / errors.Unwrap.
func (e *AppError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// New constructs an *AppError. It is a convenience for service-layer call
// sites; handlers do not typically need it.
func New(code, message string, cause error) *AppError {
	return &AppError{Code: code, Message: message, Cause: cause}
}

// UserMessage returns text safe to expose to API clients.
//
//   - If err is nil, the generic message is returned. Callers should not be
//     reaching this with nil; returning the generic string is conservative.
//   - If err's chain (errors.As) contains a non-nil *AppError, its Message is
//     returned verbatim — this is how service-layer code opts in to surfacing
//     specific user-facing prose.
//   - Otherwise, the generic message is returned. The original err MUST be
//     logged separately by the caller for operator visibility.
//
// Never log err and ALSO call response with err.Error() — use this helper
// for the response body and the structured logger for the diagnostic.
func UserMessage(err error) string {
	if err == nil {
		return genericInternalErrorMessage
	}
	var ae *AppError
	if errors.As(err, &ae) && ae != nil && ae.Message != "" {
		return ae.Message
	}
	return genericInternalErrorMessage
}

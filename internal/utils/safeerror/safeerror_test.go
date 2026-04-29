package safeerror_test

import (
	"errors"
	"fmt"
	"testing"

	"paigram/internal/utils/safeerror"
)

func TestUserMessage_KnownAppError(t *testing.T) {
	ae := &safeerror.AppError{Code: "USER_NOT_FOUND", Message: "user not found"}
	if got := safeerror.UserMessage(ae); got != "user not found" {
		t.Fatalf("UserMessage(AppError) = %q, want %q", got, "user not found")
	}
}

func TestUserMessage_UnknownGormError(t *testing.T) {
	// Mimics a raw MySQL duplicate-key error string that must NOT reach the
	// client; this is precisely what V13 was filed against.
	err := errors.New("Error 1062: Duplicate entry 'x' for key 'users.email'")
	got := safeerror.UserMessage(err)
	if got != "internal server error" {
		t.Fatalf("UserMessage(raw mysql) = %q, want %q (must not echo db text)", got, "internal server error")
	}
}

func TestUserMessage_WrappedAppError(t *testing.T) {
	// errors.As must traverse fmt.Errorf("%w") chains so the user-safe
	// message is preserved even when service code wraps for context.
	ae := &safeerror.AppError{Code: "EMAIL_TAKEN", Message: "email already exists"}
	wrapped := fmt.Errorf("update user: %w", ae)
	if got := safeerror.UserMessage(wrapped); got != "email already exists" {
		t.Fatalf("UserMessage(wrapped) = %q, want %q", got, "email already exists")
	}
}

func TestUserMessage_NilError(t *testing.T) {
	// Documented behavior: nil collapses to the generic message. Callers
	// should not be invoking UserMessage with nil, but the helper is total.
	if got := safeerror.UserMessage(nil); got != "internal server error" {
		t.Fatalf("UserMessage(nil) = %q, want %q", got, "internal server error")
	}
}

func TestUserMessage_AppErrorWithEmptyMessage_FallsBackToGeneric(t *testing.T) {
	// An *AppError with an empty Message should not leak an empty response;
	// fall back to the generic text so clients always get something
	// non-empty and safe.
	ae := &safeerror.AppError{Code: "X"}
	if got := safeerror.UserMessage(ae); got != "internal server error" {
		t.Fatalf("UserMessage(empty-message AppError) = %q, want %q", got, "internal server error")
	}
}

func TestAppError_ErrorReturnsMessage(t *testing.T) {
	ae := &safeerror.AppError{Code: "X", Message: "boom"}
	if got := ae.Error(); got != "boom" {
		t.Fatalf("AppError.Error() = %q, want %q", got, "boom")
	}
}

func TestAppError_UnwrapReturnsCause(t *testing.T) {
	cause := errors.New("db down")
	ae := &safeerror.AppError{Code: "X", Message: "service unavailable", Cause: cause}
	if got := errors.Unwrap(ae); got != cause {
		t.Fatalf("errors.Unwrap(ae) = %v, want %v", got, cause)
	}
	if !errors.Is(ae, cause) {
		t.Fatalf("errors.Is(ae, cause) = false, want true")
	}
}

func TestNew_ConstructsAppError(t *testing.T) {
	cause := errors.New("inner")
	ae := safeerror.New("CODE_X", "user message", cause)
	if ae.Code != "CODE_X" || ae.Message != "user message" || ae.Cause != cause {
		t.Fatalf("New() = %+v, fields not preserved", ae)
	}
}

package platformbinding

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	serviceplatform "paigram/internal/service/platform"
)

var (
	ErrBindingAlreadyOwned           = errors.New("platform binding is already owned by another user")
	ErrBindingRuntimeSummaryNotReady = errors.New("platform binding runtime summary is not ready")
	ErrBindingNotFound               = errors.New("platform binding not found")
	ErrCredentialGatewayUnavailable  = errors.New("platform credential orchestration is unavailable")
	ErrCredentialValidationFailed    = errors.New("platform credential validation failed")
	ErrConsumerNotSupported          = errors.New("consumer is not supported")
	ErrGrantNotFound                 = errors.New("consumer grant not found")
	ErrMultiplePrimaryProfiles       = errors.New("multiple primary profiles are not supported")
	ErrPrimaryProfileNotOwned        = errors.New("primary profile must belong to binding")
)

func IsExecutionPlaneUnavailableError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrCredentialGatewayUnavailable) || errors.Is(err, serviceplatform.ErrPlatformServiceUnavailable) || errors.Is(err, serviceplatform.ErrPlatformSummaryProxyUnavailable) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if st, ok := grpcstatus.FromError(err); ok {
		switch st.Code() {
		case codes.Unavailable, codes.DeadlineExceeded:
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") || strings.Contains(msg, "dial")
}

func IsCredentialValidationError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrCredentialValidationFailed) {
		return true
	}
	if st, ok := grpcstatus.FromError(err); ok {
		switch st.Code() {
		case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied, codes.Unauthenticated:
			return true
		}
	}
	return false
}

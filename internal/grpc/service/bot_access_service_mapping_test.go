package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"paigram/internal/service/botaccess"
)

func TestMapBotAccessErrorUsesConsumerBindingSemantics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		err     error
		code    codes.Code
		message string
	}{
		{name: "missing consumer grant", err: botaccess.ErrBotGrantNotFound, code: codes.PermissionDenied, message: "consumer grant required for binding"},
		{name: "revoked consumer grant", err: botaccess.ErrBotGrantRevoked, code: codes.PermissionDenied, message: "consumer grant revoked for binding"},
		{name: "binding already linked", err: botaccess.ErrPlatformAccountOwnedByOtherUser, code: codes.AlreadyExists, message: "platform account already bound"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapped := mapBotAccessError("test operation", tt.err)
			st := status.Convert(mapped)
			assert.Equal(t, tt.code, st.Code())
			assert.Equal(t, tt.message, st.Message())
		})
	}
}

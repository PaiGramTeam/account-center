package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"paigram/internal/config"
)

func TestNewGRPCServerBuildsRegisteredServer(t *testing.T) {
	t.Parallel()

	grpcServer, err := NewGRPCServer(50051, nil, nil, &config.Config{
		Auth: config.AuthConfig{
			ServiceTicketTTLSeconds: 300,
			ServiceTicketIssuer:     "paigram-account-center",
			ServiceTicketSigningKey: "0123456789abcdef0123456789abcdef",
		},
	})

	require.NoError(t, err)
	require.NotNil(t, grpcServer)
	require.NotNil(t, grpcServer.server)
}

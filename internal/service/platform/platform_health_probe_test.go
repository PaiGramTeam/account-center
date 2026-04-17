package platform

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
)

type delayedHealthServer struct {
	grpc_health_v1.UnimplementedHealthServer
	status grpc_health_v1.HealthCheckResponse_ServingStatus
	delay  time.Duration
}

func (s *delayedHealthServer) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	return &grpc_health_v1.HealthCheckResponse{Status: s.status}, nil
}

func TestGRPCHealthCheckerCheckHealthy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(server, healthServer)

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		<-serveErrCh
	})

	checker := newGRPCHealthChecker(500 * time.Millisecond)
	result := checker.Check(context.Background(), listener.Addr().String())

	require.Equal(t, RuntimeStateHealthy, result.State)
	require.Empty(t, result.Error)
	require.False(t, result.CheckedAt.IsZero())
}

func TestGRPCHealthCheckerCheckUnreachable(t *testing.T) {
	checker := newGRPCHealthChecker(200 * time.Millisecond)
	result := checker.Check(context.Background(), "127.0.0.1:1")

	require.Equal(t, RuntimeStateUnreachable, result.State)
	require.NotEmpty(t, result.Error)
	require.False(t, result.CheckedAt.IsZero())
}

func TestGRPCHealthCheckerCheckHealthyWithSeparateDialAndRPCBudgets(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := grpc.NewServer()
	grpc_health_v1.RegisterHealthServer(server, &delayedHealthServer{
		status: grpc_health_v1.HealthCheckResponse_SERVING,
		delay:  120 * time.Millisecond,
	})

	serveErrCh := make(chan error, 1)
	go func() {
		time.Sleep(120 * time.Millisecond)
		serveErrCh <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		<-serveErrCh
	})

	checker := newGRPCHealthChecker(200 * time.Millisecond)
	result := checker.Check(context.Background(), listener.Addr().String())

	require.Equal(t, RuntimeStateHealthy, result.State)
	require.Empty(t, result.Error)
	require.False(t, result.CheckedAt.IsZero())
}

func TestGRPCHealthCheckerCheckUnknownStatus(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	grpc_health_v1.RegisterHealthServer(server, healthServer)

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		<-serveErrCh
	})

	checker := newGRPCHealthChecker(500 * time.Millisecond)
	result := checker.Check(context.Background(), listener.Addr().String())

	require.Equal(t, RuntimeStateUnknown, result.State)
	require.NotEmpty(t, result.Error)
	require.False(t, result.CheckedAt.IsZero())
}

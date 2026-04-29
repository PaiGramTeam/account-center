package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type testHTTPServer struct {
	called bool
	err    error
}

func (s *testHTTPServer) Shutdown(context.Context) error {
	s.called = true
	return s.err
}

type testGRPCServer struct {
	called bool
}

func (s *testGRPCServer) Stop() {
	s.called = true
}

type testShutdowner struct {
	called bool
}

func (s *testShutdowner) Shutdown() {
	s.called = true
}

type testCloser struct {
	called bool
	err    error
}

func (s *testCloser) Close() error {
	s.called = true
	return s.err
}

func TestShutdownServicesStopsAllTargets(t *testing.T) {
	httpServer := &testHTTPServer{}
	grpcServer := &testGRPCServer{}
	asynqServer := &testShutdowner{}
	asynqScheduler := &testShutdowner{}
	emailService := &testCloser{}

	err := shutdownServices(context.Background(), shutdownTargets{
		httpServer:     httpServer,
		grpcServer:     grpcServer,
		asynqServer:    asynqServer,
		asynqScheduler: asynqScheduler,
		emailService:   emailService,
	})

	require.NoError(t, err)
	require.True(t, httpServer.called)
	require.True(t, grpcServer.called)
	require.True(t, asynqServer.called)
	require.True(t, asynqScheduler.called)
	require.True(t, emailService.called)
}

func TestShutdownServicesAggregatesErrors(t *testing.T) {
	httpErr := errors.New("http shutdown failed")
	emailErr := errors.New("email close failed")

	err := shutdownServices(context.Background(), shutdownTargets{
		httpServer:   &testHTTPServer{err: httpErr},
		emailService: &testCloser{err: emailErr},
	})

	require.Error(t, err)
	require.ErrorIs(t, err, httpErr)
	require.ErrorIs(t, err, emailErr)
}

// TestHTTPServerHasTimeouts verifies that the HTTP server constructed
// for production use has Slowloris-resistant timeouts and a bounded
// header size. V16: HTTP server has no timeouts.
func TestHTTPServerHasTimeouts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	srv := buildHTTPServer("127.0.0.1:0", engine)

	require.NotNil(t, srv)
	require.Equal(t, "127.0.0.1:0", srv.Addr)
	require.NotZero(t, srv.ReadHeaderTimeout, "ReadHeaderTimeout must be set to mitigate Slowloris")
	require.NotZero(t, srv.ReadTimeout, "ReadTimeout must be set")
	require.NotZero(t, srv.WriteTimeout, "WriteTimeout must be set")
	require.NotZero(t, srv.IdleTimeout, "IdleTimeout must be set")
	require.Greater(t, srv.MaxHeaderBytes, 0, "MaxHeaderBytes must be bounded")
}

package cmd

import (
	"context"
	"errors"
	"testing"

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

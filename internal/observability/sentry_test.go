package observability

import (
	"runtime/debug"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"paigram/internal/config"
)

func TestShouldIgnoreRequestURL(t *testing.T) {
	require.True(t, shouldIgnoreRequestURL("https://example.com/healthz"))
	require.False(t, shouldIgnoreRequestURL("https://example.com/api/v1/users"))
	require.False(t, shouldIgnoreRequestURL("://bad-url"))
}

func TestFlushTimeout(t *testing.T) {
	require.Equal(t, 2*time.Second, flushTimeout(config.SentryConfig{}))
	require.Equal(t, 5*time.Second, flushTimeout(config.SentryConfig{FlushTimeout: 5}))
}

func TestShouldCaptureGRPCStatus(t *testing.T) {
	require.True(t, shouldCaptureGRPCStatus(codes.Internal))
	require.True(t, shouldCaptureGRPCStatus(codes.Unavailable))
	require.False(t, shouldCaptureGRPCStatus(codes.InvalidArgument))
	require.False(t, shouldCaptureGRPCStatus(codes.NotFound))
}

func TestResolveReleaseFallsBackToConfig(t *testing.T) {
	buildRelease := releaseFromBuildInfo()
	resolved := resolveRelease(config.SentryConfig{Release: "configured-release"})

	if buildRelease != "" {
		require.Equal(t, buildRelease, resolved)
		return
	}

	require.Equal(t, "configured-release", resolved)
}

func TestBuildSetting(t *testing.T) {
	info := &debug.BuildInfo{
		Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abc123"}},
	}

	require.Equal(t, "abc123", buildSetting(info, "vcs.revision"))
	require.Empty(t, buildSetting(info, "missing"))
}

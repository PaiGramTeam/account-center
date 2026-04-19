//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"

	"paigram/internal/service/platform"
)

func TestPlatformServiceAdminRoutes(t *testing.T) {
	stack := newIntegrationStack(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- grpcServer.Serve(listener)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
		<-serveErrCh
	})

	userID, accessToken, _, _, _ := registerAndLogin(t, stack, fmt.Sprintf("platform-admin-%d@example.com", time.Now().UnixNano()), "AdminPass123!")
	grantAdminRoleToUser(t, stack, userID)

	createResp := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/admin/system/platform-services", map[string]any{
		"platform_key":      "mihomo",
		"display_name":      "Mihomo",
		"service_key":       "platform-mihomo-service",
		"service_audience":  "mihomo.platform",
		"discovery_type":    "static",
		"endpoint":          listener.Addr().String(),
		"enabled":           true,
		"supported_actions": []string{"bind_credential"},
		"credential_schema": map[string]any{"type": "object"},
	}, authHeaders(accessToken))
	require.Equal(t, http.StatusCreated, createResp.Code, createResp.Body.String())

	var createBody struct {
		Code    int                    `json:"code"`
		Message string                 `json:"message"`
		Data    map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(createResp.Body.Bytes(), &createBody))
	require.Equal(t, http.StatusCreated, createBody.Code)
	require.Equal(t, "created successfully", createBody.Message)
	require.Equal(t, "mihomo", createBody.Data["platform_key"])
	createdID, ok := createBody.Data["id"].(float64)
	require.True(t, ok, "expected numeric platform service id, got %T", createBody.Data["id"])

	checkResp := performJSONRequest(t, stack.Router, http.MethodPost, fmt.Sprintf("/api/v1/admin/system/platform-services/%d/check", uint64(createdID)), nil, authHeaders(accessToken))
	require.Equal(t, http.StatusOK, checkResp.Code, checkResp.Body.String())

	var checkBody struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(checkResp.Body.Bytes(), &checkBody))
	require.Equal(t, string(platform.RuntimeStateHealthy), checkBody.Data["runtime_state"])
}

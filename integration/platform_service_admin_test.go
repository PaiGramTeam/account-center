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

	internalcasbin "paigram/internal/casbin"
	"paigram/internal/model"
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
	grantPlatformRegistryPolicies(t, stack, userID,
		model.BuildPermissionName(model.ResourcePlatform, model.ActionCreate),
		model.BuildPermissionName(model.ResourcePlatform, model.ActionRead),
	)

	createResp := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/platform-services", map[string]any{
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

	checkResp := performJSONRequest(t, stack.Router, http.MethodPost, fmt.Sprintf("/api/v1/platform-services/%d/check", uint64(createdID)), nil, authHeaders(accessToken))
	require.Equal(t, http.StatusOK, checkResp.Code, checkResp.Body.String())

	var checkBody struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(checkResp.Body.Bytes(), &checkBody))
	require.Equal(t, string(platform.RuntimeStateHealthy), checkBody.Data["runtime_state"])
}

func grantPlatformRegistryPolicies(t *testing.T, stack *integrationStack, userID uint64, permissionNames ...string) {
	t.Helper()

	role := model.Role{
		Name:        fmt.Sprintf("platform-admin-%d", time.Now().UnixNano()),
		DisplayName: "Platform Admin",
		Description: "integration test platform admin role",
	}
	require.NoError(t, stack.DB.Create(&role).Error)

	enforcer := internalcasbin.GetEnforcer()
	require.NotNil(t, enforcer)

	for _, permissionName := range permissionNames {
		for _, policy := range internalcasbin.PoliciesForPermission(permissionName) {
			_, err := enforcer.AddPolicy(fmt.Sprint(role.ID), policy.Path, policy.Method)
			require.NoError(t, err)
		}
	}

	require.NoError(t, stack.DB.Create(&model.UserRole{UserID: userID, RoleID: role.ID, GrantedBy: userID}).Error)
}

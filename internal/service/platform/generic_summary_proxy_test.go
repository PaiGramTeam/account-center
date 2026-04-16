package platform

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	platformv1 "github.com/PaiGramTeam/proto-contracts/platform/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestGRPCGenericSummaryProxyGetCredentialSummary(t *testing.T) {
	server := &genericPlatformServiceStub{
		response: &platformv1.GetCredentialSummaryResponse{
			PlatformAccountId: "hoyo_ref_11_10001",
			Status:            platformv1.CredentialStatus_CREDENTIAL_STATUS_ACTIVE,
			LastValidatedAt:   timestamppb.New(time.Date(2026, 4, 16, 10, 11, 12, 0, time.UTC)),
			LastRefreshedAt:   timestamppb.New(time.Date(2026, 4, 16, 10, 15, 0, 0, time.UTC)),
			Devices: []*platformv1.DeviceSummary{{
				DeviceId:   "dev-1",
				DeviceFp:   "fp-1",
				DeviceName: "Chrome on Windows",
				IsValid:    true,
				LastSeenAt: timestamppb.New(time.Date(2026, 4, 16, 9, 0, 0, 0, time.UTC)),
			}},
			Profiles: []*platformv1.ProfileSummary{{
				Id:                42,
				PlatformAccountId: "hoyo_ref_11_10001",
				GameBiz:           "hk4e_global",
				Region:            "os_usa",
				PlayerId:          "10001",
				Nickname:          "Traveler",
				Level:             60,
				IsDefault:         true,
			}},
		},
	}

	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	platformv1.RegisterPlatformServiceServer(grpcServer, server)

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- grpcServer.Serve(listener)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
		<-serveErrCh
	})

	proxy := NewGRPCGenericSummaryProxy(func(ctx context.Context, endpoint string) (*grpc.ClientConn, error) {
		require.Equal(t, "bufnet", endpoint)
		return grpc.DialContext(ctx, "passthrough:///bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
	})

	summary, err := proxy.GetCredentialSummary(context.Background(), "bufnet", "ticket-123", "hoyo_ref_11_10001")
	require.NoError(t, err)
	require.Equal(t, "ticket-123", server.lastRequest.GetServiceTicket())
	require.Equal(t, "hoyo_ref_11_10001", server.lastRequest.GetPlatformAccountId())
	require.Equal(t, map[string]any{
		"platform_account_id": "hoyo_ref_11_10001",
		"status":              "active",
		"last_validated_at":   "2026-04-16T10:11:12Z",
		"last_refreshed_at":   "2026-04-16T10:15:00Z",
		"devices": []map[string]any{{
			"device_id":    "dev-1",
			"device_fp":    "fp-1",
			"device_name":  "Chrome on Windows",
			"is_valid":     true,
			"last_seen_at": "2026-04-16T09:00:00Z",
		}},
		"profiles": []map[string]any{{
			"id":                  uint64(42),
			"platform_account_id": "hoyo_ref_11_10001",
			"game_biz":            "hk4e_global",
			"region":              "os_usa",
			"player_id":           "10001",
			"nickname":            "Traveler",
			"level":               int32(60),
			"is_default":          true,
		}},
	}, summary)
}

func TestGRPCGenericSummaryProxyPropagatesRPCError(t *testing.T) {
	proxy := NewGRPCGenericSummaryProxy(func(ctx context.Context, endpoint string) (*grpc.ClientConn, error) {
		return nil, errors.New("dial failed")
	})

	_, err := proxy.GetCredentialSummary(context.Background(), "bufnet", "ticket-123", "hoyo_ref_11_10001")
	require.Error(t, err)
}

type genericPlatformServiceStub struct {
	platformv1.UnimplementedPlatformServiceServer
	response    *platformv1.GetCredentialSummaryResponse
	lastRequest *platformv1.GetCredentialSummaryRequest
}

func (s *genericPlatformServiceStub) GetCredentialSummary(_ context.Context, req *platformv1.GetCredentialSummaryRequest) (*platformv1.GetCredentialSummaryResponse, error) {
	s.lastRequest = req
	return s.response, nil
}

package platform

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"testing"

	platformv1 "github.com/PaiGramTeam/proto-contracts/platform/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	"paigram/internal/model"
)

func TestGRPCGenericCredentialGatewayPutCredential(t *testing.T) {
	stub := &genericCredentialGatewayStub{putResponse: &platformv1.PutCredentialResponse{Summary: &platformv1.GetCredentialSummaryResponse{
		PlatformAccountId: "binding_101_10001",
		Status:            platformv1.CredentialStatus_CREDENTIAL_STATUS_ACTIVE,
		LastValidatedAt:   timestamppb.Now(),
	}}}
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	platformv1.RegisterPlatformServiceServer(server, stub)
	go server.Serve(listener)
	defer server.Stop()

	gateway := NewGRPCGenericCredentialGateway(func(ctx context.Context, _ string) (*grpc.ClientConn, error) {
		return grpc.DialContext(ctx, "passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	})

	summary, err := gateway.PutCredential(context.Background(), "bufnet", "ticket-123", &model.PlatformAccountBinding{ExternalAccountKey: sql.NullString{String: "binding_101_10001", Valid: true}}, json.RawMessage(`{"cookie_bundle":"abc"}`))
	require.NoError(t, err)
	require.Equal(t, "binding_101_10001", stub.lastPut.PlatformAccountId)
	require.Equal(t, "ticket-123", stub.lastPut.ServiceTicket)
	require.Equal(t, `{"cookie_bundle":"abc"}`, stub.lastPut.CredentialPayloadJson)
	require.Equal(t, "binding_101_10001", summary["platform_account_id"])
}

func TestGRPCGenericCredentialGatewayDeleteCredentialUsesResolvedAccountKey(t *testing.T) {
	stub := &genericCredentialGatewayStub{deleteResponse: &platformv1.DeleteCredentialResponse{Success: true}}
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	platformv1.RegisterPlatformServiceServer(server, stub)
	go server.Serve(listener)
	defer server.Stop()

	gateway := NewGRPCGenericCredentialGateway(func(ctx context.Context, _ string) (*grpc.ClientConn, error) {
		return grpc.DialContext(ctx, "passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	})

	err := gateway.DeleteCredential(context.Background(), "bufnet", "ticket-123", &model.PlatformAccountBinding{ExternalAccountKey: sql.NullString{String: "binding_101_10001", Valid: true}})
	require.NoError(t, err)
	require.Equal(t, "binding_101_10001", stub.lastDelete.PlatformAccountId)
	require.Equal(t, "ticket-123", stub.lastDelete.ServiceTicket)
}

type genericCredentialGatewayStub struct {
	platformv1.UnimplementedPlatformServiceServer
	putResponse    *platformv1.PutCredentialResponse
	refreshResponse *platformv1.RefreshCredentialResponse
	deleteResponse *platformv1.DeleteCredentialResponse
	lastPut        *platformv1.PutCredentialRequest
	lastRefresh    *platformv1.RefreshCredentialRequest
	lastDelete     *platformv1.DeleteCredentialRequest
}

func (s *genericCredentialGatewayStub) DescribePlatform(context.Context, *platformv1.DescribePlatformRequest) (*platformv1.DescribePlatformResponse, error) {
	return &platformv1.DescribePlatformResponse{}, nil
}

func (s *genericCredentialGatewayStub) GetCredentialSummary(context.Context, *platformv1.GetCredentialSummaryRequest) (*platformv1.GetCredentialSummaryResponse, error) {
	return &platformv1.GetCredentialSummaryResponse{}, nil
}

func (s *genericCredentialGatewayStub) PutCredential(_ context.Context, req *platformv1.PutCredentialRequest) (*platformv1.PutCredentialResponse, error) {
	s.lastPut = req
	return s.putResponse, nil
}

func (s *genericCredentialGatewayStub) RefreshCredential(_ context.Context, req *platformv1.RefreshCredentialRequest) (*platformv1.RefreshCredentialResponse, error) {
	s.lastRefresh = req
	if s.refreshResponse == nil {
		return &platformv1.RefreshCredentialResponse{}, nil
	}
	return s.refreshResponse, nil
}

func (s *genericCredentialGatewayStub) DeleteCredential(_ context.Context, req *platformv1.DeleteCredentialRequest) (*platformv1.DeleteCredentialResponse, error) {
	s.lastDelete = req
	if s.deleteResponse == nil {
		return &platformv1.DeleteCredentialResponse{Success: true}, nil
	}
	return s.deleteResponse, nil
}

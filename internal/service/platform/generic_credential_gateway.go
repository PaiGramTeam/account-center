package platform

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	platformv1 "github.com/PaiGramTeam/proto-contracts/platform/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"paigram/internal/model"
)

type GRPCGenericCredentialGateway struct {
	dial dialFunc
}

func NewGRPCGenericCredentialGateway(dial dialFunc) *GRPCGenericCredentialGateway {
	if dial == nil {
		dial = func(ctx context.Context, endpoint string) (*grpc.ClientConn, error) {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			return grpc.DialContext(ctx, endpoint,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithBlock(),
			)
		}
	}

	return &GRPCGenericCredentialGateway{dial: dial}
}

func (g *GRPCGenericCredentialGateway) PutCredential(ctx context.Context, endpoint, ticket string, binding *model.PlatformAccountBinding, payload json.RawMessage) (map[string]any, error) {
	conn, err := g.dial(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := platformv1.NewPlatformServiceClient(conn).PutCredential(callCtx, &platformv1.PutCredentialRequest{
		ServiceTicket:        ticket,
		PlatformAccountId:    nullableBindingExternalAccountKey(binding.ExternalAccountKey),
		CredentialPayloadJson: string(payload),
	})
	if err != nil {
		return nil, err
	}
	if resp.GetSummary() == nil {
		return nil, errors.New("credential summary is required")
	}

	return mapGenericSummaryResponse(resp.GetSummary()), nil
}

func (g *GRPCGenericCredentialGateway) RefreshCredential(ctx context.Context, endpoint, ticket string, binding *model.PlatformAccountBinding) error {
	conn, err := g.dial(ctx, endpoint)
	if err != nil {
		return err
	}
	defer conn.Close()

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err = platformv1.NewPlatformServiceClient(conn).RefreshCredential(callCtx, &platformv1.RefreshCredentialRequest{
		ServiceTicket:     ticket,
		PlatformAccountId: nullableBindingExternalAccountKey(binding.ExternalAccountKey),
	})
	return err
}

func (g *GRPCGenericCredentialGateway) DeleteCredential(ctx context.Context, endpoint, ticket string, binding *model.PlatformAccountBinding) error {
	conn, err := g.dial(ctx, endpoint)
	if err != nil {
		return err
	}
	defer conn.Close()

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err = platformv1.NewPlatformServiceClient(conn).DeleteCredential(callCtx, &platformv1.DeleteCredentialRequest{
		ServiceTicket:     ticket,
		PlatformAccountId: nullableBindingExternalAccountKey(binding.ExternalAccountKey),
	})
	return err
}

func mapGenericSummaryResponse(resp *platformv1.GetCredentialSummaryResponse) map[string]any {
	return map[string]any{
		"platform_account_id": resp.GetPlatformAccountId(),
		"status":              mapGenericCredentialStatus(resp.GetStatus()),
		"last_validated_at":   formatProtoTime(resp.GetLastValidatedAt()),
		"last_refreshed_at":   formatProtoTime(resp.GetLastRefreshedAt()),
		"devices":             buildGenericDeviceSummaries(resp.GetDevices()),
		"profiles":            buildGenericProfileSummaries(resp.GetProfiles()),
	}
}

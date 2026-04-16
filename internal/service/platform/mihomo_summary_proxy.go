package platform

import (
	"context"
	"time"

	mihomov1 "github.com/PaiGramTeam/proto-contracts/mihomo/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type dialFunc func(ctx context.Context, endpoint string) (*grpc.ClientConn, error)

type GRPCSummaryProxy struct {
	dial dialFunc
}

func NewGRPCSummaryProxy(dial dialFunc) *GRPCSummaryProxy {
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

	return &GRPCSummaryProxy{dial: dial}
}

func (p *GRPCSummaryProxy) GetCredentialSummary(ctx context.Context, endpoint, ticket, platformAccountID string) (map[string]any, error) {
	conn, err := p.dial(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := mihomov1.NewMihomoCredentialServiceClient(conn).GetCredentialSummary(callCtx, &mihomov1.GetCredentialSummaryRequest{
		ServiceTicket:     ticket,
		PlatformAccountId: platformAccountID,
	})
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"platform_account_id": resp.GetPlatformAccountId(),
		"status":              mapCredentialStatus(resp.GetStatus()),
		"last_validated_at":   formatProtoTime(resp.GetLastValidatedAt()),
		"last_refreshed_at":   formatProtoTime(resp.GetLastRefreshedAt()),
		"devices":             buildDeviceSummaries(resp.GetDevices()),
		"profiles":            buildProfileSummaries(resp.GetProfiles()),
	}, nil
}

func buildDeviceSummaries(devices []*mihomov1.DeviceSummary) []map[string]any {
	views := make([]map[string]any, 0, len(devices))
	for _, device := range devices {
		views = append(views, map[string]any{
			"device_id":    device.GetDeviceId(),
			"device_fp":    device.GetDeviceFp(),
			"device_name":  device.GetDeviceName(),
			"is_valid":     device.GetIsValid(),
			"last_seen_at": formatProtoTime(device.GetLastSeenAt()),
		})
	}

	return views
}

func buildProfileSummaries(profiles []*mihomov1.ProfileSummary) []map[string]any {
	views := make([]map[string]any, 0, len(profiles))
	for _, profile := range profiles {
		views = append(views, map[string]any{
			"id":                  profile.GetId(),
			"platform_account_id": profile.GetPlatformAccountId(),
			"game_biz":            profile.GetGameBiz(),
			"region":              profile.GetRegion(),
			"player_id":           profile.GetPlayerId(),
			"nickname":            profile.GetNickname(),
			"level":               profile.GetLevel(),
			"is_default":          profile.GetIsDefault(),
		})
	}

	return views
}

func formatProtoTime(value *timestamppb.Timestamp) any {
	if value == nil {
		return nil
	}

	return value.AsTime().UTC().Format(time.RFC3339)
}

func mapCredentialStatus(status mihomov1.CredentialStatus) string {
	switch status {
	case mihomov1.CredentialStatus_CREDENTIAL_STATUS_ACTIVE:
		return "active"
	case mihomov1.CredentialStatus_CREDENTIAL_STATUS_EXPIRED:
		return "expired"
	case mihomov1.CredentialStatus_CREDENTIAL_STATUS_INVALID:
		return "invalid"
	case mihomov1.CredentialStatus_CREDENTIAL_STATUS_CHALLENGE_REQUIRED:
		return "challenge_required"
	default:
		return "unspecified"
	}
}

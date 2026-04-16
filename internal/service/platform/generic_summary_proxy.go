package platform

import (
	"context"
	"time"

	platformv1 "github.com/PaiGramTeam/proto-contracts/platform/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type GRPCGenericSummaryProxy struct {
	dial dialFunc
}

func NewGRPCGenericSummaryProxy(dial dialFunc) *GRPCGenericSummaryProxy {
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

	return &GRPCGenericSummaryProxy{dial: dial}
}

func (p *GRPCGenericSummaryProxy) GetCredentialSummary(ctx context.Context, endpoint, ticket, platformAccountID string) (map[string]any, error) {
	conn, err := p.dial(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := platformv1.NewPlatformServiceClient(conn).GetCredentialSummary(callCtx, &platformv1.GetCredentialSummaryRequest{
		ServiceTicket:     ticket,
		PlatformAccountId: platformAccountID,
	})
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"platform_account_id": resp.GetPlatformAccountId(),
		"status":              mapGenericCredentialStatus(resp.GetStatus()),
		"last_validated_at":   formatProtoTime(resp.GetLastValidatedAt()),
		"last_refreshed_at":   formatProtoTime(resp.GetLastRefreshedAt()),
		"devices":             buildGenericDeviceSummaries(resp.GetDevices()),
		"profiles":            buildGenericProfileSummaries(resp.GetProfiles()),
	}, nil
}

func buildGenericDeviceSummaries(devices []*platformv1.DeviceSummary) []map[string]any {
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

func buildGenericProfileSummaries(profiles []*platformv1.ProfileSummary) []map[string]any {
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

func mapGenericCredentialStatus(status platformv1.CredentialStatus) string {
	switch status {
	case platformv1.CredentialStatus_CREDENTIAL_STATUS_ACTIVE:
		return "active"
	case platformv1.CredentialStatus_CREDENTIAL_STATUS_EXPIRED:
		return "expired"
	case platformv1.CredentialStatus_CREDENTIAL_STATUS_INVALID:
		return "invalid"
	case platformv1.CredentialStatus_CREDENTIAL_STATUS_CHALLENGE_REQUIRED:
		return "challenge_required"
	default:
		return "unspecified"
	}
}

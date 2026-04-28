package platformbinding

import (
	"context"
	"encoding/json"
	"time"

	platformv1 "github.com/PaiGramTeam/proto-contracts/platform/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"paigram/internal/model"
	serviceaudit "paigram/internal/service/audit"

	"gorm.io/gorm"
)

type ServiceGroup struct {
	BindingService           BindingService
	GrantService             GrantService
	ProfileProjectionService ProfileProjectionService
	OrchestrationService     OrchestrationService
	RuntimeSummaryService    RuntimeSummaryService
}

func NewServiceGroup(db *gorm.DB, platformService interface {
	orchestrationPlatformService
	runtimeSummaryPlatformService
}, dependencies ...any) *ServiceGroup {
	bindingService := NewBindingService(db)
	profileProjectionService := NewProfileProjectionService(db)
	grantDependencies := append([]any{platformService}, dependencies...)
	grantService := NewGrantService(db, grantDependencies...)
	auditService := serviceaudit.NewAuditService(db)
	gateway := credentialGateway(defaultGenericCredentialGateway{})
	for _, dependency := range dependencies {
		if candidate, ok := dependency.(credentialGateway); ok {
			gateway = candidate
		}
	}
	return &ServiceGroup{
		BindingService:           *bindingService,
		GrantService:             *grantService,
		ProfileProjectionService: *profileProjectionService,
		OrchestrationService:     *NewOrchestrationService(bindingService, platformService, gateway, profileProjectionService, grantService, auditService),
		RuntimeSummaryService:    *NewRuntimeSummaryService(platformService, bindingService, profileProjectionService),
	}
}

type defaultGenericCredentialGateway struct{}

func (defaultGenericCredentialGateway) PutCredential(ctx context.Context, endpoint, ticket string, binding *model.PlatformAccountBinding, payload json.RawMessage) (map[string]any, error) {
	conn, err := dialGenericPlatform(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := platformv1.NewPlatformServiceClient(conn).PutCredential(callCtx, &platformv1.PutCredentialRequest{
		ServiceTicket:         ticket,
		PlatformAccountId:     bindingExternalAccountKey(binding),
		CredentialPayloadJson: string(payload),
	})
	if err != nil {
		return nil, err
	}
	return genericCredentialSummaryMap(resp.GetSummary()), nil
}

func (defaultGenericCredentialGateway) RefreshCredential(ctx context.Context, endpoint, ticket string, binding *model.PlatformAccountBinding) error {
	conn, err := dialGenericPlatform(ctx, endpoint)
	if err != nil {
		return err
	}
	defer conn.Close()

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err = platformv1.NewPlatformServiceClient(conn).RefreshCredential(callCtx, &platformv1.RefreshCredentialRequest{
		ServiceTicket:     ticket,
		PlatformAccountId: bindingExternalAccountKey(binding),
	})
	return err
}

func (defaultGenericCredentialGateway) DeleteCredential(ctx context.Context, endpoint, ticket string, binding *model.PlatformAccountBinding) error {
	conn, err := dialGenericPlatform(ctx, endpoint)
	if err != nil {
		return err
	}
	defer conn.Close()

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err = platformv1.NewPlatformServiceClient(conn).DeleteCredential(callCtx, &platformv1.DeleteCredentialRequest{
		ServiceTicket:     ticket,
		PlatformAccountId: bindingExternalAccountKey(binding),
	})
	return err
}

func dialGenericPlatform(ctx context.Context, endpoint string) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return grpc.DialContext(ctx, endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
}

func bindingExternalAccountKey(binding *model.PlatformAccountBinding) string {
	if binding == nil || !binding.ExternalAccountKey.Valid {
		return ""
	}
	return binding.ExternalAccountKey.String
}

func genericCredentialSummaryMap(resp *platformv1.GetCredentialSummaryResponse) map[string]any {
	if resp == nil {
		return map[string]any{}
	}
	return map[string]any{
		"platform_account_id": resp.GetPlatformAccountId(),
		"status":              genericCredentialStatus(resp.GetStatus()),
		"profiles":            genericProfileSummaries(resp.GetProfiles()),
	}
}

func genericCredentialStatus(status platformv1.CredentialStatus) string {
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

func genericProfileSummaries(profiles []*platformv1.ProfileSummary) []map[string]any {
	items := make([]map[string]any, 0, len(profiles))
	for _, profile := range profiles {
		items = append(items, map[string]any{
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
	return items
}

package service

import (
	"context"
	"database/sql"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "paigram/internal/grpc/pb/v1"
	"paigram/internal/model"
	"paigram/internal/service/botaccess"
)

// BotAccessService exposes bot account reference operations over generated gRPC bindings.
type BotAccessService struct {
	pb.UnimplementedBotAccessServiceServer

	accountRefService *botaccess.AccountRefService
	ticketService     *botaccess.TicketService
}

func NewBotAccessService(accountRefService *botaccess.AccountRefService, ticketService *botaccess.TicketService) *BotAccessService {
	return &BotAccessService{
		accountRefService: accountRefService,
		ticketService:     ticketService,
	}
}

func (s *BotAccessService) ResolveBotUser(ctx context.Context, req *pb.ResolveBotUserRequest) (*pb.ResolveBotUserResponse, error) {
	bot, err := botFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetExternalUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "external_user_id is required")
	}

	identity, err := s.accountRefService.ResolveBotUser(bot.Id, req.GetExternalUserId())
	if err != nil {
		return nil, mapBotAccessError("resolve bot user", err)
	}

	return &pb.ResolveBotUserResponse{
		UserId:           identity.UserID,
		BotId:            identity.BotID,
		ExternalUserId:   identity.ExternalUserID,
		ExternalUsername: nullStringValue(identity.ExternalUsername),
	}, nil
}

func (s *BotAccessService) LinkPlatformAccount(ctx context.Context, req *pb.LinkPlatformAccountRequest) (*pb.LinkPlatformAccountResponse, error) {
	bot, err := botFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetExternalUserId() == "" || req.GetPlatform() == "" || req.GetPlatformServiceKey() == "" || req.GetPlatformAccountId() == "" || req.GetDisplayName() == "" {
		return nil, status.Error(codes.InvalidArgument, "external_user_id, platform, platform_service_key, platform_account_id, and display_name are required")
	}

	ref, created, err := s.accountRefService.LinkPlatformAccount(botaccess.LinkPlatformAccountParams{
		BotID:              bot.Id,
		ExternalUserID:     req.GetExternalUserId(),
		Platform:           req.GetPlatform(),
		PlatformServiceKey: req.GetPlatformServiceKey(),
		PlatformAccountID:  req.GetPlatformAccountId(),
		DisplayName:        req.GetDisplayName(),
		MetaJSON:           req.GetMetaJson(),
		GrantScopes:        req.GetGrantScopes(),
	})
	if err != nil {
		return nil, mapBotAccessError("link platform account", err)
	}

	return &pb.LinkPlatformAccountResponse{Account: platformAccountRefToProto(*ref), Created: created}, nil
}

func (s *BotAccessService) ListAccessibleAccounts(ctx context.Context, req *pb.ListAccessibleAccountsRequest) (*pb.ListAccessibleAccountsResponse, error) {
	bot, err := botFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetExternalUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "external_user_id is required")
	}

	refs, err := s.accountRefService.ListAccessibleAccounts(bot.Id, req.GetExternalUserId(), req.GetPlatform())
	if err != nil {
		return nil, mapBotAccessError("list accessible accounts", err)
	}

	accounts := make([]*pb.PlatformAccountRef, 0, len(refs))
	for _, ref := range refs {
		accounts = append(accounts, platformAccountRefToProto(ref))
	}

	return &pb.ListAccessibleAccountsResponse{Accounts: accounts}, nil
}

func (s *BotAccessService) IssueServiceTicket(ctx context.Context, req *pb.IssueServiceTicketRequest) (*pb.IssueServiceTicketResponse, error) {
	bot, err := botFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetExternalUserId() == "" || req.GetPlatformAccountRefId() == 0 || req.GetAudience() == "" {
		return nil, status.Error(codes.InvalidArgument, "external_user_id, platform_account_ref_id, and audience are required")
	}

	identity, ref, grant, err := s.accountRefService.GetGrantedAccount(bot.Id, req.GetExternalUserId(), req.GetPlatformAccountRefId())
	if err != nil {
		return nil, mapBotAccessError("get granted account", err)
	}
	if req.GetAudience() != ref.PlatformServiceKey {
		return nil, status.Error(codes.InvalidArgument, "audience does not match platform service key")
	}

	grantedScopes, err := botaccess.DecodeGrantScopes(*grant)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "decode grant scopes: %v", err)
	}

	scopes, err := selectTicketScopes(grantedScopes, req.GetRequestedScopes())
	if err != nil {
		return nil, mapBotAccessError("validate requested scopes", err)
	}

	ticket, expiresAt, err := s.ticketService.Issue(bot.Id, ref, identity.UserID, scopes, req.GetAudience())
	if err != nil {
		return nil, mapBotAccessError("issue service ticket", err)
	}

	return &pb.IssueServiceTicketResponse{
		Ticket:    ticket,
		Audience:  req.GetAudience(),
		ExpiresAt: timestamppb.New(expiresAt),
		Account:   platformAccountRefToProto(*ref),
	}, nil
}

func botFromContext(ctx context.Context) (*Bot, error) {
	bot, ok := ctx.Value("bot").(*Bot)
	if !ok || bot == nil {
		return nil, status.Error(codes.Unauthenticated, "bot context missing")
	}

	return bot, nil
}

func platformAccountRefToProto(ref model.PlatformAccountRef) *pb.PlatformAccountRef {
	status := pb.PlatformAccountStatus_PLATFORM_ACCOUNT_STATUS_UNSPECIFIED
	switch ref.Status {
	case model.PlatformAccountRefStatusActive:
		status = pb.PlatformAccountStatus_PLATFORM_ACCOUNT_STATUS_ACTIVE
	case model.PlatformAccountRefStatusInactive:
		status = pb.PlatformAccountStatus_PLATFORM_ACCOUNT_STATUS_INACTIVE
	case model.PlatformAccountRefStatusRevoked:
		status = pb.PlatformAccountStatus_PLATFORM_ACCOUNT_STATUS_REVOKED
	}

	return &pb.PlatformAccountRef{
		Id:                 ref.ID,
		UserId:             ref.UserID,
		Platform:           ref.Platform,
		PlatformServiceKey: ref.PlatformServiceKey,
		PlatformAccountId:  ref.PlatformAccountID,
		DisplayName:        ref.DisplayName,
		Status:             status,
		MetaJson:           nullStringValue(ref.MetaJSON),
		CreatedAt:          timestamppb.New(ref.CreatedAt),
		UpdatedAt:          timestamppb.New(ref.UpdatedAt),
	}
}

func nullStringValue(value sql.NullString) string {
	if !value.Valid {
		return ""
	}

	return value.String
}

func selectTicketScopes(grantedScopes, requestedScopes []string) ([]string, error) {
	if len(requestedScopes) == 0 {
		return grantedScopes, nil
	}

	granted := make(map[string]struct{}, len(grantedScopes))
	for _, scope := range grantedScopes {
		granted[scope] = struct{}{}
	}

	for _, scope := range requestedScopes {
		if _, ok := granted[scope]; !ok {
			return nil, botaccess.ErrScopeNotGranted
		}
	}

	return requestedScopes, nil
}

func mapBotAccessError(operation string, err error) error {
	switch {
	case errors.Is(err, botaccess.ErrBotIdentityNotFound):
		return status.Error(codes.NotFound, "bot identity not found")
	case errors.Is(err, botaccess.ErrPlatformAccountMissing):
		return status.Error(codes.NotFound, "platform account ref not found")
	case errors.Is(err, botaccess.ErrBotGrantNotFound):
		return status.Error(codes.NotFound, "bot account grant not found")
	case errors.Is(err, botaccess.ErrBotGrantRevoked):
		return status.Error(codes.PermissionDenied, "bot account grant revoked")
	case errors.Is(err, botaccess.ErrScopeNotGranted):
		return status.Error(codes.PermissionDenied, "requested scope is not granted")
	case errors.Is(err, botaccess.ErrPlatformAccountOwnedByOtherUser):
		return status.Error(codes.AlreadyExists, "platform account ref is owned by another user")
	case errors.Is(err, botaccess.ErrInactiveAccountRef):
		return status.Error(codes.FailedPrecondition, "platform account ref is not active")
	case errors.Is(err, botaccess.ErrInvalidTicketConfig):
		return status.Error(codes.FailedPrecondition, "invalid service ticket config")
	default:
		return status.Errorf(codes.Internal, "%s: %v", operation, err)
	}
}

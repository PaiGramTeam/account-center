package service

import (
	"context"
	"database/sql"
	"errors"
	"strconv"

	"google.golang.org/grpc/codes"
	grpcmetadata "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"

	pb "paigram/internal/grpc/pb/v1"
	"paigram/internal/model"
	serviceaudit "paigram/internal/service/audit"
	"paigram/internal/service/botaccess"
)

// BotAccessService exposes bot binding operations over generated gRPC bindings.
type BotAccessService struct {
	pb.UnimplementedBotAccessServiceServer

	accountRefService *botaccess.AccountRefService
	ticketService     *botaccess.TicketService
	db                *gorm.DB
}

func NewBotAccessService(accountRefService *botaccess.AccountRefService, ticketService *botaccess.TicketService, db *gorm.DB) *BotAccessService {
	return &BotAccessService{
		accountRefService: accountRefService,
		ticketService:     ticketService,
		db:                db,
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

func (s *BotAccessService) UpsertPlatformBinding(ctx context.Context, req *pb.UpsertPlatformBindingRequest) (*pb.UpsertPlatformBindingResponse, error) {
	bot, err := botFromContext(ctx)
	if err != nil {
		return nil, err
	}
	allowed, err := s.accountRefService.BotAllowsLegacyBindingWrite(bot.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load bot capability: %v", err)
	}
	if !allowed {
		s.recordLegacyBindingAudit(ctx, bot, req, "legacy_binding_write_reject", "failure", "legacy_binding_write_not_allowed")
		return nil, status.Error(codes.PermissionDenied, "legacy platform binding write is migration-only")
	}
	if req.GetExternalUserId() == "" || req.GetPlatform() == "" || req.GetPlatformServiceKey() == "" || req.GetPlatformAccountId() == "" || req.GetDisplayName() == "" {
		return nil, status.Error(codes.InvalidArgument, "external_user_id, platform, platform_service_key, platform_account_id, and display_name are required")
	}

	binding, created, err := s.accountRefService.UpsertPlatformBinding(botaccess.UpsertPlatformBindingParams{
		BotID:              bot.Id,
		ExternalUserID:     req.GetExternalUserId(),
		Platform:           req.GetPlatform(),
		PlatformServiceKey: req.GetPlatformServiceKey(),
		PlatformAccountID:  req.GetPlatformAccountId(),
		DisplayName:        req.GetDisplayName(),
		MetaJSON:           req.GetMetaJson(),
		GrantScopes:        req.GetGrantScopes(),
		GrantMode:          botaccess.PlatformBindingGrantModeLegacyMigration,
	})
	if err != nil {
		return nil, mapBotAccessError("upsert platform binding", err)
	}
	s.recordLegacyBindingAudit(ctx, bot, req, "legacy_binding_write", "success", "")

	return &pb.UpsertPlatformBindingResponse{Binding: platformBindingToProto(*binding), Created: created}, nil
}

func (s *BotAccessService) ListAccessibleBindings(ctx context.Context, req *pb.ListAccessibleBindingsRequest) (*pb.ListAccessibleBindingsResponse, error) {
	bot, err := botFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetExternalUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "external_user_id is required")
	}

	bindings, err := s.accountRefService.ListAccessibleBindings(bot.Id, req.GetExternalUserId(), req.GetPlatform())
	if err != nil {
		return nil, mapBotAccessError("list accessible bindings", err)
	}

	items := make([]*pb.PlatformAccountBinding, 0, len(bindings))
	for _, binding := range bindings {
		items = append(items, platformBindingToProto(binding))
	}

	return &pb.ListAccessibleBindingsResponse{Bindings: items}, nil
}

func (s *BotAccessService) IssueServiceTicket(ctx context.Context, req *pb.IssueServiceTicketRequest) (*pb.IssueServiceTicketResponse, error) {
	bot, err := botFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetExternalUserId() == "" || req.GetBindingId() == 0 || req.GetAudience() == "" {
		return nil, status.Error(codes.InvalidArgument, "external_user_id, binding_id, and audience are required")
	}

	_, binding, grant, err := s.accountRefService.GetGrantedBinding(bot.Id, req.GetExternalUserId(), req.GetBindingId(), req.GetProfileId())
	if err != nil {
		s.recordTicketAudit(ctx, bot, nil, req, "ticket_reject", "failure", reasonCodeFromBotAccessErr(err), nil)
		return nil, mapBotAccessError("get granted binding", err)
	}
	if req.GetAudience() != binding.PlatformServiceKey {
		s.recordTicketAudit(ctx, bot, binding, req, "ticket_reject", "failure", "audience_mismatch", nil)
		return nil, status.Error(codes.InvalidArgument, "audience does not match binding platform service key")
	}
	grantedScopes, err := s.accountRefService.GetGrantedScopes(bot.Id, binding.ID)
	if err != nil {
		s.recordTicketAudit(ctx, bot, binding, req, "ticket_reject", "failure", reasonCodeFromBotAccessErr(err), nil)
		return nil, mapBotAccessError("get granted scopes", err)
	}
	scopes, err := selectTicketScopes(grantedScopes, req.GetRequestedScopes())
	if err != nil {
		s.recordTicketAudit(ctx, bot, binding, req, "ticket_reject", "failure", reasonCodeFromBotAccessErr(err), nil)
		return nil, mapBotAccessError("validate requested scopes", err)
	}

	ticket, expiresAt, err := s.ticketService.Issue(bot.Id, grant.Consumer, binding, scopes, req.GetAudience(), req.GetProfileId(), grant.TicketVersion)
	if err != nil {
		s.recordTicketAudit(ctx, bot, binding, req, "ticket_reject", "failure", reasonCodeFromBotAccessErr(err), map[string]any{"consumer": grant.Consumer})
		return nil, mapBotAccessError("issue service ticket", err)
	}
	s.recordTicketAudit(ctx, bot, binding, req, "ticket_issue", "success", "", map[string]any{"consumer": grant.Consumer, "scopes": scopes})

	return &pb.IssueServiceTicketResponse{
		Ticket:    ticket,
		Audience:  req.GetAudience(),
		ExpiresAt: timestamppb.New(expiresAt),
		Binding:   platformBindingToProto(*binding),
	}, nil
}

func botFromContext(ctx context.Context) (*Bot, error) {
	bot, ok := ctx.Value("bot").(*Bot)
	if !ok || bot == nil {
		return nil, status.Error(codes.Unauthenticated, "bot context missing")
	}

	return bot, nil
}

func platformBindingToProto(binding model.PlatformAccountBinding) *pb.PlatformAccountBinding {
	status := pb.PlatformAccountStatus_PLATFORM_ACCOUNT_STATUS_UNSPECIFIED
	switch binding.Status {
	case model.PlatformAccountBindingStatusActive:
		status = pb.PlatformAccountStatus_PLATFORM_ACCOUNT_STATUS_ACTIVE
	case model.PlatformAccountBindingStatusDeleted, model.PlatformAccountBindingStatusDeleting:
		status = pb.PlatformAccountStatus_PLATFORM_ACCOUNT_STATUS_REVOKED
	default:
		status = pb.PlatformAccountStatus_PLATFORM_ACCOUNT_STATUS_INACTIVE
	}

	return &pb.PlatformAccountBinding{
		Id:                 binding.ID,
		UserId:             binding.OwnerUserID,
		Platform:           binding.Platform,
		PlatformServiceKey: binding.PlatformServiceKey,
		PlatformAccountId:  nullStringValue(binding.ExternalAccountKey),
		DisplayName:        binding.DisplayName,
		Status:             status,
		CreatedAt:          timestamppb.New(binding.CreatedAt),
		UpdatedAt:          timestamppb.New(binding.UpdatedAt),
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
		return status.Error(codes.NotFound, "platform account binding not found")
	case errors.Is(err, botaccess.ErrBotGrantNotFound):
		return status.Error(codes.PermissionDenied, "consumer grant required for binding")
	case errors.Is(err, botaccess.ErrBotGrantRevoked):
		return status.Error(codes.PermissionDenied, "consumer grant revoked for binding")
	case errors.Is(err, botaccess.ErrConsumerNotSupported):
		return status.Error(codes.InvalidArgument, "consumer is not supported")
	case errors.Is(err, botaccess.ErrScopeNotGranted):
		return status.Error(codes.PermissionDenied, "requested scope is not granted")
	case errors.Is(err, botaccess.ErrPlatformAccountOwnedByOtherUser):
		return status.Error(codes.AlreadyExists, "platform account already bound")
	case errors.Is(err, botaccess.ErrPlatformServiceNotEnabled):
		return status.Error(codes.InvalidArgument, "platform service is not enabled for platform")
	case errors.Is(err, botaccess.ErrInactiveAccountRef):
		return status.Error(codes.FailedPrecondition, "platform account binding is not active")
	case errors.Is(err, botaccess.ErrInvalidTicketConfig):
		return status.Error(codes.FailedPrecondition, "invalid service ticket config")
	default:
		return status.Errorf(codes.Internal, "%s: %v", operation, err)
	}
}

func (s *BotAccessService) recordTicketAudit(ctx context.Context, bot *Bot, binding *model.PlatformAccountBinding, req *pb.IssueServiceTicketRequest, action, result, reasonCode string, metadata map[string]any) {
	if s == nil || s.db == nil || bot == nil || req == nil {
		return
	}
	var bindingID *uint64
	var ownerUserID *uint64
	targetID := strconv.FormatUint(req.GetBindingId(), 10)
	if binding != nil {
		bindingID = &binding.ID
		targetID = strconv.FormatUint(binding.ID, 10)
		ownerUserID = &binding.OwnerUserID
	}
	writeMetadata := map[string]any{"bot_id": bot.Id, "external_user_id": req.GetExternalUserId(), "audience": req.GetAudience()}
	for key, value := range metadata {
		writeMetadata[key] = value
	}
	_ = serviceaudit.Record(ctx, s.db, serviceaudit.WriteInput{
		Category:    "bot_access",
		ActorType:   "consumer",
		Action:      action,
		TargetType:  "binding",
		TargetID:    targetID,
		BindingID:   bindingID,
		OwnerUserID: ownerUserID,
		Result:      result,
		ReasonCode:  reasonCode,
		RequestID:   requestIDFromGRPCContext(ctx),
		Metadata:    writeMetadata,
	})
}

func (s *BotAccessService) recordLegacyBindingAudit(ctx context.Context, bot *Bot, req *pb.UpsertPlatformBindingRequest, action, result, reasonCode string) {
	if s == nil || s.db == nil || bot == nil || req == nil {
		return
	}

	_ = serviceaudit.Record(ctx, s.db, serviceaudit.WriteInput{
		Category:   "bot_access",
		ActorType:  "consumer",
		Action:     action,
		TargetType: "platform_binding",
		TargetID:   req.GetPlatformAccountId(),
		Result:     result,
		ReasonCode: reasonCode,
		RequestID:  requestIDFromGRPCContext(ctx),
		Metadata: map[string]any{
			"bot_id":               bot.Id,
			"external_user_id":     req.GetExternalUserId(),
			"platform":             req.GetPlatform(),
			"platform_service_key": req.GetPlatformServiceKey(),
			"legacy_migration":     true,
		},
	})
}

func requestIDFromGRPCContext(ctx context.Context) string {
	if md, ok := grpcmetadata.FromIncomingContext(ctx); ok {
		if values := md.Get("x-request-id"); len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func reasonCodeFromBotAccessErr(err error) string {
	switch {
	case errors.Is(err, botaccess.ErrBotIdentityNotFound):
		return "bot_identity_not_found"
	case errors.Is(err, botaccess.ErrPlatformAccountMissing):
		return "platform_account_missing"
	case errors.Is(err, botaccess.ErrBotGrantNotFound):
		return "bot_grant_not_found"
	case errors.Is(err, botaccess.ErrBotGrantRevoked):
		return "bot_grant_revoked"
	case errors.Is(err, botaccess.ErrConsumerNotSupported):
		return "consumer_not_supported"
	case errors.Is(err, botaccess.ErrScopeNotGranted):
		return "scope_not_granted"
	case errors.Is(err, botaccess.ErrPlatformAccountOwnedByOtherUser):
		return "binding_owned_by_other_user"
	case errors.Is(err, botaccess.ErrInactiveAccountRef):
		return "inactive_account_ref"
	case errors.Is(err, botaccess.ErrInvalidTicketConfig):
		return "invalid_ticket_config"
	default:
		return "internal_error"
	}
}

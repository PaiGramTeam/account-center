package service

import (
	"context"

	pb "paigram/internal/grpc/pb/v1"
)

// BotAuthServiceAdapter exposes the existing hand-written bot auth service through generated gRPC bindings.
type BotAuthServiceAdapter struct {
	pb.UnimplementedBotAuthServiceServer

	core *BotAuthService
}

func NewBotAuthServiceAdapter(core *BotAuthService) *BotAuthServiceAdapter {
	return &BotAuthServiceAdapter{core: core}
}

func (a *BotAuthServiceAdapter) RegisterBot(ctx context.Context, req *pb.RegisterBotRequest) (*pb.RegisterBotResponse, error) {
	resp, err := a.core.RegisterBot(ctx, &RegisterBotRequest{
		Name:        req.GetName(),
		Description: req.GetDescription(),
		Type:        BotType(req.GetType()),
		Scopes:      req.GetScopes(),
		OwnerEmail:  req.GetOwnerEmail(),
	})
	if err != nil {
		return nil, err
	}

	return &pb.RegisterBotResponse{
		Bot:       serviceBotToProto(resp.Bot),
		ApiKey:    resp.ApiKey,
		ApiSecret: resp.ApiSecret,
	}, nil
}

func (a *BotAuthServiceAdapter) BotLogin(ctx context.Context, req *pb.BotLoginRequest) (*pb.BotLoginResponse, error) {
	resp, err := a.core.BotLogin(ctx, &BotLoginRequest{
		ApiKey:    req.GetApiKey(),
		ApiSecret: req.GetApiSecret(),
	})
	if err != nil {
		return nil, err
	}

	return &pb.BotLoginResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresIn:    resp.ExpiresIn,
		TokenType:    resp.TokenType,
		Bot:          serviceBotToProto(resp.Bot),
	}, nil
}

func (a *BotAuthServiceAdapter) RefreshBotToken(ctx context.Context, req *pb.RefreshBotTokenRequest) (*pb.RefreshBotTokenResponse, error) {
	resp, err := a.core.RefreshBotToken(ctx, &RefreshBotTokenRequest{RefreshToken: req.GetRefreshToken()})
	if err != nil {
		return nil, err
	}

	return &pb.RefreshBotTokenResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresIn:    resp.ExpiresIn,
		TokenType:    resp.TokenType,
	}, nil
}

func (a *BotAuthServiceAdapter) ValidateBotToken(ctx context.Context, req *pb.ValidateBotTokenRequest) (*pb.ValidateBotTokenResponse, error) {
	resp, err := a.core.ValidateBotToken(ctx, &ValidateBotTokenRequest{AccessToken: req.GetAccessToken()})
	if err != nil {
		return nil, err
	}

	return &pb.ValidateBotTokenResponse{
		Valid:     resp.Valid,
		Bot:       serviceBotToProto(resp.Bot),
		Scopes:    resp.Scopes,
		ExpiresAt: resp.ExpiresAt,
	}, nil
}

func (a *BotAuthServiceAdapter) RevokeBotToken(ctx context.Context, req *pb.RevokeBotTokenRequest) (*pb.RevokeBotTokenResponse, error) {
	resp, err := a.core.RevokeBotToken(ctx, &RevokeBotTokenRequest{AccessToken: req.GetAccessToken()})
	if err != nil {
		return nil, err
	}

	return &pb.RevokeBotTokenResponse{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

func (a *BotAuthServiceAdapter) GetBotInfo(ctx context.Context, req *pb.GetBotInfoRequest) (*pb.GetBotInfoResponse, error) {
	resp, err := a.core.GetBotInfo(ctx, &GetBotInfoRequest{BotId: req.GetBotId()})
	if err != nil {
		return nil, err
	}

	return &pb.GetBotInfoResponse{Bot: serviceBotToProto(resp.Bot)}, nil
}

func serviceBotToProto(bot *Bot) *pb.Bot {
	if bot == nil {
		return nil
	}

	return &pb.Bot{
		Id:           bot.Id,
		Name:         bot.Name,
		Description:  bot.Description,
		Type:         pb.BotType(bot.Type),
		Status:       pb.BotStatus(bot.Status),
		Scopes:       bot.Scopes,
		CreatedAt:    bot.CreatedAt,
		UpdatedAt:    bot.UpdatedAt,
		LastActiveAt: bot.LastActiveAt,
	}
}

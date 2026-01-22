package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"

	"paigram/internal/model"
)

// BotAuthService implements the gRPC BotAuthService
type BotAuthService struct {
	UnimplementedBotAuthServiceServer
	db                   *gorm.DB
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
}

// NewBotAuthService creates a new bot auth service
func NewBotAuthService(db *gorm.DB) *BotAuthService {
	return &BotAuthService{
		db:                   db,
		accessTokenDuration:  time.Hour,
		refreshTokenDuration: time.Hour * 24 * 30, // 30 days
	}
}

// RegisterBot registers a new bot client
func (s *BotAuthService) RegisterBot(ctx context.Context, req *RegisterBotRequest) (*RegisterBotResponse, error) {
	// Validate input
	if req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "bot name is required")
	}
	if req.OwnerEmail == "" {
		return nil, status.Errorf(codes.InvalidArgument, "owner email is required")
	}

	// Find owner user
	var userEmail model.UserEmail
	if err := s.db.Where("email = ?", req.OwnerEmail).First(&userEmail).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(codes.NotFound, "owner user not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to find owner: %v", err)
	}

	// Generate bot credentials
	botID := uuid.New().String()
	apiKey := s.generateAPIKey()
	apiSecret := s.generateAPISecret()

	// Hash the API secret
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(apiSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to hash secret: %v", err)
	}

	// Create bot
	bot := &model.Bot{
		ID:          botID,
		Name:        req.Name,
		Description: req.Description,
		Type:        s.convertBotTypeToString(req.Type),
		Status:      "ACTIVE",
		OwnerUserID: userEmail.UserID,
		APIKey:      apiKey,
		APISecret:   string(hashedSecret),
		Scopes:      s.encodeScopesJSON(req.Scopes),
	}

	if err := s.db.Create(bot).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create bot: %v", err)
	}

	return &RegisterBotResponse{
		Bot:       s.modelBotToProto(bot),
		ApiKey:    apiKey,
		ApiSecret: apiSecret, // Return unhashed secret only during registration
	}, nil
}

// BotLogin authenticates a bot and returns access tokens
func (s *BotAuthService) BotLogin(ctx context.Context, req *BotLoginRequest) (*BotLoginResponse, error) {
	// Validate input
	if req.ApiKey == "" || req.ApiSecret == "" {
		return nil, status.Errorf(codes.InvalidArgument, "api key and secret are required")
	}

	// Find bot by API key
	var bot model.Bot
	if err := s.db.Where("api_key = ?", req.ApiKey).First(&bot).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
		}
		return nil, status.Errorf(codes.Internal, "failed to find bot: %v", err)
	}

	// Verify API secret
	if err := bcrypt.CompareHashAndPassword([]byte(bot.APISecret), []byte(req.ApiSecret)); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	// Check bot status
	if bot.Status != "ACTIVE" {
		return nil, status.Errorf(codes.PermissionDenied, "bot is not active")
	}

	// Generate tokens
	accessToken := s.generateToken()
	refreshToken := s.generateToken()

	// Create token record
	botToken := &model.BotToken{
		BotID:        bot.ID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(s.accessTokenDuration),
	}

	if err := s.db.Create(botToken).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create token: %v", err)
	}

	// Update last active time
	s.db.Model(&bot).Update("last_active_at", time.Now())

	return &BotLoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.accessTokenDuration.Seconds()),
		TokenType:    "Bearer",
		Bot:          s.modelBotToProto(&bot),
	}, nil
}

// RefreshBotToken refreshes an access token using a refresh token
func (s *BotAuthService) RefreshBotToken(ctx context.Context, req *RefreshBotTokenRequest) (*RefreshBotTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Errorf(codes.InvalidArgument, "refresh token is required")
	}

	// Find token record
	var botToken model.BotToken
	if err := s.db.Preload("Bot").Where("refresh_token = ? AND revoked_at IS NULL", req.RefreshToken).First(&botToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(codes.Unauthenticated, "invalid refresh token")
		}
		return nil, status.Errorf(codes.Internal, "failed to find token: %v", err)
	}

	// Check bot status
	if botToken.Bot.Status != "ACTIVE" {
		return nil, status.Errorf(codes.PermissionDenied, "bot is not active")
	}

	// Generate new access token
	newAccessToken := s.generateToken()
	newRefreshToken := s.generateToken()

	// Update token record
	botToken.AccessToken = newAccessToken
	botToken.RefreshToken = newRefreshToken
	botToken.ExpiresAt = time.Now().Add(s.accessTokenDuration)

	if err := s.db.Save(&botToken).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update token: %v", err)
	}

	// Update last active time
	s.db.Model(&botToken.Bot).Update("last_active_at", time.Now())

	return &RefreshBotTokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(s.accessTokenDuration.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// ValidateBotToken validates an access token
func (s *BotAuthService) ValidateBotToken(ctx context.Context, req *ValidateBotTokenRequest) (*ValidateBotTokenResponse, error) {
	if req.AccessToken == "" {
		return nil, status.Errorf(codes.InvalidArgument, "access token is required")
	}

	// Find token record
	var botToken model.BotToken
	if err := s.db.Preload("Bot").Where("access_token = ? AND revoked_at IS NULL", req.AccessToken).First(&botToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &ValidateBotTokenResponse{Valid: false}, nil
		}
		return nil, status.Errorf(codes.Internal, "failed to find token: %v", err)
	}

	// Check if token is expired
	if time.Now().After(botToken.ExpiresAt) {
		return &ValidateBotTokenResponse{Valid: false}, nil
	}

	// Check bot status
	if botToken.Bot.Status != "ACTIVE" {
		return &ValidateBotTokenResponse{Valid: false}, nil
	}

	// Parse scopes
	scopes := s.decodeScopesJSON(botToken.Bot.Scopes)

	return &ValidateBotTokenResponse{
		Valid:     true,
		Bot:       s.modelBotToProto(&botToken.Bot),
		Scopes:    scopes,
		ExpiresAt: timestamppb.New(botToken.ExpiresAt),
	}, nil
}

// RevokeBotToken revokes an access token
func (s *BotAuthService) RevokeBotToken(ctx context.Context, req *RevokeBotTokenRequest) (*RevokeBotTokenResponse, error) {
	if req.AccessToken == "" {
		return nil, status.Errorf(codes.InvalidArgument, "access token is required")
	}

	// Find and revoke token
	result := s.db.Model(&model.BotToken{}).
		Where("access_token = ? AND revoked_at IS NULL", req.AccessToken).
		Update("revoked_at", time.Now())

	if result.Error != nil {
		return nil, status.Errorf(codes.Internal, "failed to revoke token: %v", result.Error)
	}

	if result.RowsAffected == 0 {
		return &RevokeBotTokenResponse{
			Success: false,
			Message: "token not found or already revoked",
		}, nil
	}

	return &RevokeBotTokenResponse{
		Success: true,
		Message: "token revoked successfully",
	}, nil
}

// GetBotInfo retrieves bot information
func (s *BotAuthService) GetBotInfo(ctx context.Context, req *GetBotInfoRequest) (*GetBotInfoResponse, error) {
	if req.BotId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "bot id is required")
	}

	var bot model.Bot
	if err := s.db.First(&bot, "id = ?", req.BotId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(codes.NotFound, "bot not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to get bot: %v", err)
	}

	return &GetBotInfoResponse{
		Bot: s.modelBotToProto(&bot),
	}, nil
}

// Helper functions

func (s *BotAuthService) generateAPIKey() string {
	return "pk_" + s.generateRandomString(32)
}

func (s *BotAuthService) generateAPISecret() string {
	return "sk_" + s.generateRandomString(48)
}

func (s *BotAuthService) generateToken() string {
	return s.generateRandomString(64)
}

func (s *BotAuthService) generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}

func (s *BotAuthService) encodeScopesJSON(scopes []string) string {
	if len(scopes) == 0 {
		return "[]"
	}
	data, _ := json.Marshal(scopes)
	return string(data)
}

func (s *BotAuthService) decodeScopesJSON(scopesJSON string) []string {
	var scopes []string
	json.Unmarshal([]byte(scopesJSON), &scopes)
	return scopes
}

func (s *BotAuthService) modelBotToProto(bot *model.Bot) *Bot {
	protoBot := &Bot{
		Id:          bot.ID,
		Name:        bot.Name,
		Description: bot.Description,
		Type:        s.convertStringToBotType(bot.Type),
		Status:      s.convertStringToBotStatus(bot.Status),
		Scopes:      s.decodeScopesJSON(bot.Scopes),
		CreatedAt:   timestamppb.New(bot.CreatedAt),
		UpdatedAt:   timestamppb.New(bot.UpdatedAt),
	}

	if bot.LastActiveAt.Valid {
		protoBot.LastActiveAt = timestamppb.New(bot.LastActiveAt.Time)
	}

	return protoBot
}

func (s *BotAuthService) convertBotTypeToString(botType BotType) string {
	switch botType {
	case BotType_BOT_TYPE_TELEGRAM:
		return "TELEGRAM"
	case BotType_BOT_TYPE_DISCORD:
		return "DISCORD"
	case BotType_BOT_TYPE_QQ:
		return "QQ"
	case BotType_BOT_TYPE_WECHAT:
		return "WECHAT"
	default:
		return "OTHER"
	}
}

func (s *BotAuthService) convertStringToBotType(typeStr string) BotType {
	switch strings.ToUpper(typeStr) {
	case "TELEGRAM":
		return BotType_BOT_TYPE_TELEGRAM
	case "DISCORD":
		return BotType_BOT_TYPE_DISCORD
	case "QQ":
		return BotType_BOT_TYPE_QQ
	case "WECHAT":
		return BotType_BOT_TYPE_WECHAT
	default:
		return BotType_BOT_TYPE_OTHER
	}
}

func (s *BotAuthService) convertStringToBotStatus(status string) BotStatus {
	switch strings.ToUpper(status) {
	case "ACTIVE":
		return BotStatus_BOT_STATUS_ACTIVE
	case "INACTIVE":
		return BotStatus_BOT_STATUS_INACTIVE
	case "SUSPENDED":
		return BotStatus_BOT_STATUS_SUSPENDED
	case "REVOKED":
		return BotStatus_BOT_STATUS_REVOKED
	default:
		return BotStatus_BOT_STATUS_UNSPECIFIED
	}
}

// Note: These types would normally be generated from the proto files
// For now, we'll define minimal interfaces

type UnimplementedBotAuthServiceServer struct{}

type RegisterBotRequest struct {
	Name        string
	Description string
	Type        BotType
	Scopes      []string
	OwnerEmail  string
}

type RegisterBotResponse struct {
	Bot       *Bot
	ApiKey    string
	ApiSecret string
}

type BotLoginRequest struct {
	ApiKey    string
	ApiSecret string
}

type BotLoginResponse struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	TokenType    string
	Bot          *Bot
}

type RefreshBotTokenRequest struct {
	RefreshToken string
}

type RefreshBotTokenResponse struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	TokenType    string
}

type ValidateBotTokenRequest struct {
	AccessToken string
}

type ValidateBotTokenResponse struct {
	Valid     bool
	Bot       *Bot
	Scopes    []string
	ExpiresAt *timestamppb.Timestamp
}

type RevokeBotTokenRequest struct {
	AccessToken string
}

type RevokeBotTokenResponse struct {
	Success bool
	Message string
}

type GetBotInfoRequest struct {
	BotId string
}

type GetBotInfoResponse struct {
	Bot *Bot
}

type Bot struct {
	Id           string
	Name         string
	Description  string
	Type         BotType
	Status       BotStatus
	Scopes       []string
	CreatedAt    *timestamppb.Timestamp
	UpdatedAt    *timestamppb.Timestamp
	LastActiveAt *timestamppb.Timestamp
}

type BotType int32

const (
	BotType_BOT_TYPE_UNSPECIFIED BotType = 0
	BotType_BOT_TYPE_TELEGRAM    BotType = 1
	BotType_BOT_TYPE_DISCORD     BotType = 2
	BotType_BOT_TYPE_QQ          BotType = 3
	BotType_BOT_TYPE_WECHAT      BotType = 4
	BotType_BOT_TYPE_OTHER       BotType = 99
)

type BotStatus int32

const (
	BotStatus_BOT_STATUS_UNSPECIFIED BotStatus = 0
	BotStatus_BOT_STATUS_ACTIVE      BotStatus = 1
	BotStatus_BOT_STATUS_INACTIVE    BotStatus = 2
	BotStatus_BOT_STATUS_SUSPENDED   BotStatus = 3
	BotStatus_BOT_STATUS_REVOKED     BotStatus = 4
)

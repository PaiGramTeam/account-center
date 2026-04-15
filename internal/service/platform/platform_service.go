package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/model"
	"paigram/internal/service/botaccess"
)

var (
	ErrInvalidTicketConfig             = errors.New("invalid service ticket config")
	ErrPlatformSummaryProxyUnavailable = errors.New("platform summary proxy is unavailable")
	ErrPlatformServiceUnavailable      = errors.New("platform service is unavailable")
)

// ServiceTicketClaims carries actor-scoped platform access metadata.
type ServiceTicketClaims = botaccess.ServiceTicketClaims

// PlatformListView is the browser-facing platform registry list model.
type PlatformListView struct {
	Platform         string   `json:"platform"`
	DisplayName      string   `json:"display_name"`
	SupportedActions []string `json:"supported_actions"`
}

// PlatformSchemaView is the browser-facing platform schema model.
type PlatformSchemaView struct {
	Platform         string         `json:"platform"`
	DisplayName      string         `json:"display_name"`
	SupportedActions []string       `json:"supported_actions"`
	CredentialSchema map[string]any `json:"credential_schema"`
}

type platformSummaryProxy interface {
	GetCredentialSummary(ctx context.Context, endpoint, ticket, platformAccountID string) (map[string]any, error)
}

// PlatformService provides platform registry lookups.
type PlatformService struct {
	db           *gorm.DB
	issuer       string
	ttl          time.Duration
	signingKey   []byte
	summaryProxy platformSummaryProxy
}

func buildPlatformServiceTicketClaims(actorType, actorID string, ownerUserID, platformAccountRefID uint64, platform, platformAccountID string, scopes []string) ServiceTicketClaims {
	return ServiceTicketClaims{
		ActorType:            actorType,
		ActorID:              actorID,
		OwnerUserID:          ownerUserID,
		UserID:               ownerUserID,
		Platform:             platform,
		PlatformAccountRefID: platformAccountRefID,
		PlatformAccountID:    platformAccountID,
		Scopes:               scopes,
	}
}

// ConfigureAuth loads service ticket signing settings from auth config.
func (s *PlatformService) ConfigureAuth(authCfg config.AuthConfig) error {
	if authCfg.ServiceTicketTTLSeconds <= 0 {
		return ErrInvalidTicketConfig
	}

	issuer := authCfg.ServiceTicketIssuer
	if issuer == "" {
		issuer = "paigram-account-center"
	}
	if authCfg.ServiceTicketSigningKey != "" && len(authCfg.ServiceTicketSigningKey) < 32 {
		return ErrInvalidTicketConfig
	}

	s.issuer = issuer
	s.ttl = time.Duration(authCfg.ServiceTicketTTLSeconds) * time.Second
	s.signingKey = []byte(authCfg.ServiceTicketSigningKey)

	return nil
}

// ListEnabledPlatforms returns all enabled platform registry entries.
func (s *PlatformService) ListEnabledPlatforms() ([]model.PlatformService, error) {
	var platforms []model.PlatformService
	if err := s.db.Where("enabled = ?", true).Order("platform_key ASC").Find(&platforms).Error; err != nil {
		return nil, err
	}

	return platforms, nil
}

// GetEnabledPlatform returns an enabled platform registry entry by key.
func (s *PlatformService) GetEnabledPlatform(platformKey string) (*model.PlatformService, error) {
	var platform model.PlatformService
	if err := s.db.Where("platform_key = ? AND enabled = ?", platformKey, true).First(&platform).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}

		return nil, err
	}

	return &platform, nil
}

// ListEnabledPlatformViews returns enabled platform entries decoded for handler responses.
func (s *PlatformService) ListEnabledPlatformViews() ([]PlatformListView, error) {
	platforms, err := s.ListEnabledPlatforms()
	if err != nil {
		return nil, err
	}

	views := make([]PlatformListView, 0, len(platforms))
	for _, platform := range platforms {
		supportedActions, err := parseStringListJSON(platform.SupportedActionsJSON)
		if err != nil {
			return nil, err
		}

		views = append(views, PlatformListView{
			Platform:         platform.PlatformKey,
			DisplayName:      platform.DisplayName,
			SupportedActions: supportedActions,
		})
	}

	return views, nil
}

// GetPlatformSchemaView returns a decoded schema view for an enabled platform.
func (s *PlatformService) GetPlatformSchemaView(platformKey string) (*PlatformSchemaView, error) {
	platform, err := s.GetEnabledPlatform(platformKey)
	if err != nil {
		return nil, err
	}

	supportedActions, err := parseStringListJSON(platform.SupportedActionsJSON)
	if err != nil {
		return nil, err
	}

	credentialSchema, err := parseObjectJSON(platform.CredentialSchemaJSON)
	if err != nil {
		return nil, err
	}

	return &PlatformSchemaView{
		Platform:         platform.PlatformKey,
		DisplayName:      platform.DisplayName,
		SupportedActions: supportedActions,
		CredentialSchema: credentialSchema,
	}, nil
}

// IssueActorScopedTicket signs a short-lived service ticket for a platform account ref.
func (s *PlatformService) IssueActorScopedTicket(actorType, actorID string, ownerUserID uint64, ref *model.PlatformAccountRef, scopes []string, audience string) (string, time.Time, error) {
	if len(s.signingKey) == 0 || s.ttl <= 0 {
		return "", time.Time{}, ErrInvalidTicketConfig
	}
	if ref == nil || ref.Status != model.PlatformAccountRefStatusActive {
		return "", time.Time{}, gorm.ErrRecordNotFound
	}
	if actorType == "" || actorID == "" || audience == "" {
		return "", time.Time{}, ErrInvalidTicketConfig
	}

	now := time.Now().UTC()
	expiresAt := now.Add(s.ttl)
	claims := buildPlatformServiceTicketClaims(actorType, actorID, ownerUserID, ref.ID, ref.Platform, ref.PlatformAccountID, scopes)
	if actorType == "bot" {
		claims.BotID = actorID
	}
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    s.issuer,
		Subject:   fmt.Sprintf("user:%d", ownerUserID),
		Audience:  jwt.ClaimStrings{audience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		ID:        fmt.Sprintf("%s:%s:%d:%d", actorType, actorID, ref.ID, now.UnixNano()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.signingKey)
	if err != nil {
		return "", time.Time{}, err
	}

	return signed, expiresAt, nil
}

func (s *PlatformService) SetSummaryProxy(proxy platformSummaryProxy) {
	s.summaryProxy = proxy
}

func (s *PlatformService) GetPlatformAccountSummary(ctx context.Context, actorType, actorID string, ownerUserID, platformAccountRefID uint64, scopes []string) (map[string]any, error) {
	if s.summaryProxy == nil {
		return nil, ErrPlatformSummaryProxyUnavailable
	}

	var ref model.PlatformAccountRef
	if err := s.db.WithContext(ctx).Where("id = ? AND user_id = ?", platformAccountRefID, ownerUserID).First(&ref).Error; err != nil {
		return nil, err
	}

	platform, err := s.GetEnabledPlatform(ref.Platform)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrPlatformServiceUnavailable
		}
		return nil, err
	}

	ticket, _, err := s.IssueActorScopedTicket(actorType, actorID, ownerUserID, &ref, scopes, platform.ServiceAudience)
	if err != nil {
		return nil, err
	}

	return s.summaryProxy.GetCredentialSummary(ctx, platform.Endpoint, ticket, ref.PlatformAccountID)
}

func parseStringListJSON(raw string) ([]string, error) {
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, err
	}
	return values, nil
}

func parseObjectJSON(raw string) (map[string]any, error) {
	var value map[string]any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return nil, err
	}
	return value, nil
}

package platform

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/protobuf/encoding/protowire"
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
	db                  *gorm.DB
	issuer              string
	ttl                 time.Duration
	signingKey          []byte
	dial                dialFunc
	summaryProxy        platformSummaryProxy
	genericSummaryProxy platformSummaryProxy
	healthChecker       platformHealthChecker
}

func buildPlatformServiceTicketClaims(actorType, actorID string, ownerUserID, platformAccountRefID uint64, platform, platformAccountID string, scopes []string) ServiceTicketClaims {
	return ServiceTicketClaims{
		ActorType:         actorType,
		ActorID:           actorID,
		OwnerUserID:       ownerUserID,
		UserID:            ownerUserID,
		Platform:          platform,
		BindingID:         platformAccountRefID,
		PlatformAccountID: platformAccountID,
		Scopes:            scopes,
	}
}

func buildBindingScopedTicketClaims(actorType, actorID string, ownerUserID, bindingID uint64, platform, platformServiceKey, platformAccountID string, scopes []string) ServiceTicketClaims {
	claims := buildPlatformServiceTicketClaims(actorType, actorID, ownerUserID, bindingID, platform, platformAccountID, scopes)
	claims.PlatformServiceKey = platformServiceKey
	return claims
}

func isSupportedInternalActorType(actorType string) bool {
	switch actorType {
	case "user", "admin", "consumer":
		return true
	default:
		return false
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
	if actorType == "" || actorID == "" || audience == "" || !isSupportedInternalActorType(actorType) {
		return "", time.Time{}, ErrInvalidTicketConfig
	}

	now := time.Now().UTC()
	expiresAt := now.Add(s.ttl)
	claims := buildBindingScopedTicketClaims(actorType, actorID, ownerUserID, ref.ID, ref.Platform, ref.PlatformServiceKey, ref.PlatformAccountID, scopes)
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

func (s *PlatformService) IssueBindingScopedTicket(actorType, actorID string, binding *model.PlatformAccountBinding, scopes []string) (string, time.Time, error) {
	if len(s.signingKey) == 0 || s.ttl <= 0 {
		return "", time.Time{}, ErrInvalidTicketConfig
	}
	if binding == nil || actorType == "" || actorID == "" || !isSupportedInternalActorType(actorType) {
		return "", time.Time{}, ErrInvalidTicketConfig
	}

	platformRow, err := s.GetEnabledPlatform(binding.Platform)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", time.Time{}, ErrPlatformServiceUnavailable
		}
		return "", time.Time{}, err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(s.ttl)
	claims := buildBindingScopedTicketClaims(actorType, actorID, binding.OwnerUserID, binding.ID, binding.Platform, binding.PlatformServiceKey, nullableBindingExternalAccountKey(binding.ExternalAccountKey), scopes)
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    s.issuer,
		Subject:   fmt.Sprintf("user:%d", binding.OwnerUserID),
		Audience:  jwt.ClaimStrings{platformRow.ServiceAudience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		ID:        fmt.Sprintf("%s:%s:%d:%d", actorType, actorID, binding.ID, now.UnixNano()),
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

func (s *PlatformService) SetGenericSummaryProxy(proxy platformSummaryProxy) {
	s.genericSummaryProxy = proxy
}

func (s *PlatformService) SetHealthChecker(checker platformHealthChecker) {
	s.healthChecker = checker
}

func (s *PlatformService) GetPlatformAccountSummary(ctx context.Context, actorType, actorID string, ownerUserID, platformAccountRefID uint64, scopes []string) (map[string]any, error) {
	if bindingSummary, ok, err := s.getBindingSummary(ctx, ownerUserID, platformAccountRefID); err != nil {
		return nil, err
	} else if ok {
		return bindingSummary, nil
	}

	if s.genericSummaryProxy == nil && s.summaryProxy == nil {
		return nil, gorm.ErrRecordNotFound
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

	if s.genericSummaryProxy != nil {
		return s.genericSummaryProxy.GetCredentialSummary(ctx, platform.Endpoint, ticket, ref.PlatformAccountID)
	}

	return s.summaryProxy.GetCredentialSummary(ctx, platform.Endpoint, ticket, ref.PlatformAccountID)
}

func (s *PlatformService) GetBindingRuntimeSummary(ctx context.Context, actorType, actorID string, binding *model.PlatformAccountBinding, scopes []string) (map[string]any, error) {
	if binding == nil {
		return nil, gorm.ErrRecordNotFound
	}
	if !binding.ExternalAccountKey.Valid {
		return nil, gorm.ErrRecordNotFound
	}
	if s.genericSummaryProxy == nil && s.summaryProxy == nil {
		return nil, ErrPlatformSummaryProxyUnavailable
	}

	platformRow, err := s.GetEnabledPlatform(binding.Platform)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrPlatformServiceUnavailable
		}
		return nil, err
	}

	ticket, _, err := s.IssueBindingScopedTicket(actorType, actorID, binding, scopes)
	if err != nil {
		return nil, err
	}

	platformAccountID := nullableBindingExternalAccountKey(binding.ExternalAccountKey)
	if s.genericSummaryProxy != nil {
		return s.genericSummaryProxy.GetCredentialSummary(ctx, platformRow.Endpoint, ticket, platformAccountID)
	}

	return s.summaryProxy.GetCredentialSummary(ctx, platformRow.Endpoint, ticket, platformAccountID)
}

func (s *PlatformService) ConfirmBindingPrimaryProfile(ctx context.Context, actorType, actorID string, binding *model.PlatformAccountBinding, playerID string) error {
	if binding == nil || playerID == "" || !binding.ExternalAccountKey.Valid || binding.ExternalAccountKey.String == "" {
		return gorm.ErrRecordNotFound
	}
	if binding.Platform != "mihomo" {
		return ErrPlatformServiceUnavailable
	}

	platformRow, err := s.GetEnabledPlatform(binding.Platform)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrPlatformServiceUnavailable
		}
		return err
	}

	ticket, _, err := s.IssueBindingScopedTicket(actorType, actorID, binding, []string{"mihomo.profile.write"})
	if err != nil {
		return err
	}

	dial := s.dial
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

	conn, err := dial(ctx, platformRow.Endpoint)
	if err != nil {
		return err
	}
	defer conn.Close()

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var resp []byte
	err = conn.Invoke(callCtx,
		"/mihomo.v1.MihomoAccountService/ConfirmPrimaryProfile",
		encodeConfirmPrimaryProfileRequest(ticket, nullableBindingExternalAccountKey(binding.ExternalAccountKey), playerID),
		&resp,
		grpc.ForceCodec(rawProtoCodec{}),
	)
	return err
}

type rawProtoCodec struct{}

func (rawProtoCodec) Marshal(v any) ([]byte, error) {
	bytes, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("raw proto codec expects []byte, got %T", v)
	}
	return bytes, nil
}

func (rawProtoCodec) Unmarshal(data []byte, v any) error {
	bytes, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("raw proto codec expects *[]byte, got %T", v)
	}
	*bytes = append((*bytes)[:0], data...)
	return nil
}

func (rawProtoCodec) Name() string {
	return "proto"
}

var _ encoding.Codec = rawProtoCodec{}

func encodeConfirmPrimaryProfileRequest(ticket, platformAccountID, playerID string) []byte {
	message := make([]byte, 0, len(ticket)+len(platformAccountID)+len(playerID)+8)
	message = protowire.AppendTag(message, 1, protowire.BytesType)
	message = protowire.AppendString(message, ticket)
	message = protowire.AppendTag(message, 2, protowire.BytesType)
	message = protowire.AppendString(message, platformAccountID)
	message = protowire.AppendTag(message, 3, protowire.BytesType)
	message = protowire.AppendString(message, playerID)
	return message
}

func (s *PlatformService) getBindingSummary(ctx context.Context, ownerUserID, bindingID uint64) (map[string]any, bool, error) {
	var binding model.PlatformAccountBinding
	err := s.db.WithContext(ctx).
		Preload("Profiles", func(db *gorm.DB) *gorm.DB {
			return db.Order("is_primary DESC").Order("id ASC")
		}).
		Where("id = ? AND owner_user_id = ?", bindingID, ownerUserID).
		First(&binding).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}

	profiles := make([]map[string]any, 0, len(binding.Profiles))
	for _, profile := range binding.Profiles {
		profiles = append(profiles, map[string]any{
			"id":                   profile.ID,
			"platform_profile_key": profile.PlatformProfileKey,
			"game_biz":             profile.GameBiz,
			"region":               profile.Region,
			"player_uid":           profile.PlayerUID,
			"nickname":             profile.Nickname,
			"level":                nullableBindingSummaryInt(profile.Level),
			"is_primary":           profile.IsPrimary,
			"source_updated_at":    nullableBindingSummaryTime(profile.SourceUpdatedAt),
		})
	}

	return map[string]any{
		"binding_id":            binding.ID,
		"platform":              binding.Platform,
		"external_account_key":  nullableBindingSummaryString(binding.ExternalAccountKey),
		"platform_service_key":  binding.PlatformServiceKey,
		"display_name":          binding.DisplayName,
		"status":                binding.Status,
		"status_reason_code":    binding.StatusReasonCode,
		"status_reason_message": binding.StatusReasonMessage,
		"primary_profile_id":    nullableBindingSummaryInt(binding.PrimaryProfileID),
		"last_validated_at":     nullableBindingSummaryTime(binding.LastValidatedAt),
		"last_refreshed_at":     nullableBindingSummaryTime(binding.LastSyncedAt),
		"last_synced_at":        nullableBindingSummaryTime(binding.LastSyncedAt),
		"profiles":              profiles,
	}, true, nil
}

func nullableBindingSummaryInt(value sql.NullInt64) any {
	if !value.Valid {
		return nil
	}
	return value.Int64
}

func nullableBindingSummaryTime(value sql.NullTime) any {
	if !value.Valid {
		return nil
	}
	return value.Time
}

func nullableBindingSummaryString(value sql.NullString) any {
	if !value.Valid {
		return nil
	}
	return value.String
}

func nullableBindingExternalAccountKey(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
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

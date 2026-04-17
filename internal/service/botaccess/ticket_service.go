package botaccess

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"paigram/internal/config"
	"paigram/internal/model"
)

type ServiceTicketClaims struct {
	ActorType            string   `json:"actor_type,omitempty"`
	ActorID              string   `json:"actor_id,omitempty"`
	OwnerUserID          uint64   `json:"owner_user_id,omitempty"`
	BotID                string   `json:"bot_id"`
	UserID               uint64   `json:"user_id"`
	Platform             string   `json:"platform"`
	PlatformServiceKey   string   `json:"platform_service_key"`
	BindingID            uint64   `json:"binding_id,omitempty"`
	PlatformAccountRefID uint64   `json:"platform_account_ref_id"`
	PlatformAccountID    string   `json:"platform_account_id,omitempty"`
	Scopes               []string `json:"scopes"`
	jwt.RegisteredClaims
}

type TicketService struct {
	issuer     string
	ttl        time.Duration
	signingKey []byte
}

func NewTicketService(authCfg config.AuthConfig) (*TicketService, error) {
	if authCfg.ServiceTicketSigningKey == "" || authCfg.ServiceTicketTTLSeconds <= 0 {
		return nil, ErrInvalidTicketConfig
	}

	issuer := authCfg.ServiceTicketIssuer
	if issuer == "" {
		issuer = "paigram-account-center"
	}

	return &TicketService{
		issuer:     issuer,
		ttl:        time.Duration(authCfg.ServiceTicketTTLSeconds) * time.Second,
		signingKey: []byte(authCfg.ServiceTicketSigningKey),
	}, nil
}

func (s *TicketService) Issue(botID string, ref *model.PlatformAccountRef, userID uint64, scopes []string, audience string) (string, time.Time, error) {
	if ref == nil || ref.Status != model.PlatformAccountRefStatusActive {
		return "", time.Time{}, ErrInactiveAccountRef
	}
	if audience == "" {
		return "", time.Time{}, ErrInvalidTicketConfig
	}

	now := time.Now().UTC()
	expiresAt := now.Add(s.ttl)
	claims := ServiceTicketClaims{
		ActorType:            "bot",
		ActorID:              botID,
		OwnerUserID:          userID,
		BotID:                botID,
		UserID:               userID,
		Platform:             ref.Platform,
		PlatformServiceKey:   ref.PlatformServiceKey,
		BindingID:            ref.ID,
		PlatformAccountRefID: ref.ID,
		PlatformAccountID:    ref.PlatformAccountID,
		Scopes:               scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   fmt.Sprintf("user:%d", userID),
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			ID:        fmt.Sprintf("%s:%d:%d", botID, ref.ID, now.UnixNano()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.signingKey)
	if err != nil {
		return "", time.Time{}, err
	}

	return signed, expiresAt, nil
}

func DecodeGrantScopes(grant model.BotAccountGrant) ([]string, error) {
	if grant.Scopes == "" {
		return []string{}, nil
	}

	var scopes []string
	if err := json.Unmarshal([]byte(grant.Scopes), &scopes); err != nil {
		return nil, err
	}

	return scopes, nil
}

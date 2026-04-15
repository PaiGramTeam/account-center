package botaccess

import (
	"testing"
	"time"

	"paigram/internal/config"
	"paigram/internal/model"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTicketServiceRejectsEmptySigningKey(t *testing.T) {
	service, err := NewTicketService(config.AuthConfig{
		ServiceTicketTTLSeconds: 300,
		ServiceTicketIssuer:     "issuer",
	})
	require.ErrorIs(t, err, ErrInvalidTicketConfig)
	assert.Nil(t, service)
}

func TestTicketServiceIssueIncludesAudienceAndScopes(t *testing.T) {
	service, err := NewTicketService(config.AuthConfig{
		ServiceTicketTTLSeconds: 300,
		ServiceTicketIssuer:     "issuer",
		ServiceTicketSigningKey: "super-secret",
	})
	require.NoError(t, err)

	ref := &model.PlatformAccountRef{
		ID:                 42,
		UserID:             100,
		Platform:           "telegram",
		PlatformServiceKey: "tg-main",
		PlatformAccountID:  "acct-42",
		DisplayName:        "Primary",
		Status:             model.PlatformAccountRefStatusActive,
	}

	tokenString, expiresAt, err := service.Issue("bot-ticket", ref, ref.UserID, []string{"profile:read", "messages:send"}, "platform-service")
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().UTC().Add(5*time.Minute), expiresAt, 3*time.Second)

	parsed := &ServiceTicketClaims{}
	token, err := jwt.ParseWithClaims(tokenString, parsed, func(token *jwt.Token) (any, error) {
		return []byte("super-secret"), nil
	})
	require.NoError(t, err)
	require.True(t, token.Valid)
	assert.Equal(t, "bot", parsed.ActorType)
	assert.Equal(t, "bot-ticket", parsed.ActorID)
	assert.Equal(t, ref.UserID, parsed.OwnerUserID)
	assert.Equal(t, "bot-ticket", parsed.BotID)
	assert.Equal(t, ref.UserID, parsed.UserID)
	assert.Equal(t, ref.Platform, parsed.Platform)
	assert.Equal(t, ref.PlatformServiceKey, parsed.PlatformServiceKey)
	assert.Equal(t, ref.ID, parsed.PlatformAccountRefID)
	assert.Equal(t, ref.PlatformAccountID, parsed.PlatformAccountID)
	assert.ElementsMatch(t, []string{"profile:read", "messages:send"}, parsed.Scopes)
	assert.Equal(t, "issuer", parsed.Issuer)
	assert.Equal(t, "user:100", parsed.Subject)
	assert.Equal(t, []string{"platform-service"}, []string(parsed.Audience))
	assert.WithinDuration(t, expiresAt, parsed.ExpiresAt.Time, time.Second)
	assert.NotEmpty(t, parsed.ID)
}

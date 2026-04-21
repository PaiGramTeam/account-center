package botaccess

import (
	"database/sql"
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

	binding := &model.PlatformAccountBinding{
		ID:                 42,
		OwnerUserID:        100,
		Platform:           "telegram",
		ExternalAccountKey: sql.NullString{String: "acct-42", Valid: true},
		PlatformServiceKey: "tg-main",
		DisplayName:        "Primary",
		Status:             model.PlatformAccountBindingStatusActive,
	}

	tokenString, expiresAt, err := service.Issue("bot-ticket", "paigram-bot", binding, []string{"profile:read", "messages:send"}, "platform-service")
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().UTC().Add(5*time.Minute), expiresAt, 3*time.Second)

	parsed := &ServiceTicketClaims{}
	token, err := jwt.ParseWithClaims(tokenString, parsed, func(token *jwt.Token) (any, error) {
		return []byte("super-secret"), nil
	})
	require.NoError(t, err)
	require.True(t, token.Valid)
	assert.Equal(t, "consumer", parsed.ActorType)
	assert.Equal(t, "paigram-bot", parsed.ActorID)
	assert.Equal(t, "paigram-bot", parsed.Consumer)
	assert.Equal(t, binding.OwnerUserID, parsed.OwnerUserID)
	assert.Equal(t, "bot-ticket", parsed.BotID)
	assert.Equal(t, binding.OwnerUserID, parsed.UserID)
	assert.Equal(t, binding.Platform, parsed.Platform)
	assert.Equal(t, binding.PlatformServiceKey, parsed.PlatformServiceKey)
	assert.Equal(t, binding.ID, parsed.BindingID)
	assert.Equal(t, binding.ID, parsed.PlatformAccountRefID)
	assert.Equal(t, "acct-42", parsed.PlatformAccountID)
	assert.ElementsMatch(t, []string{"profile:read", "messages:send"}, parsed.Scopes)
	assert.Equal(t, "issuer", parsed.Issuer)
	assert.Equal(t, "user:100", parsed.Subject)
	assert.Equal(t, []string{"platform-service"}, []string(parsed.Audience))
	assert.WithinDuration(t, expiresAt, parsed.ExpiresAt.Time, time.Second)
	assert.NotEmpty(t, parsed.ID)
}

package config

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestSetDefaultsIncludesSentry(t *testing.T) {
	v := viper.New()
	setDefaults(v)

	require.False(t, v.GetBool("sentry.enabled"))
	require.Empty(t, v.GetString("sentry.dsn"))
	require.Equal(t, "development", v.GetString("sentry.environment"))
	require.Empty(t, v.GetString("sentry.release"))
	require.False(t, v.GetBool("sentry.debug"))
	require.True(t, v.GetBool("sentry.attach_stacktrace"))
	require.Equal(t, 1.0, v.GetFloat64("sentry.sample_rate"))
	require.Equal(t, 0.0, v.GetFloat64("sentry.traces_sample_rate"))
	require.Equal(t, 2, v.GetInt("sentry.flush_timeout"))
}

func TestSetDefaultsIncludesServiceTicketSettings(t *testing.T) {
	v := viper.New()
	setDefaults(v)

	require.Equal(t, 300, v.GetInt("auth.service_ticket_ttl"))
	require.Equal(t, "paigram-account-center", v.GetString("auth.service_ticket_issuer"))
	require.Empty(t, v.GetString("auth.service_ticket_signing_key"))
}

func TestValidateServiceTicketConfigRejectsShortSigningKey(t *testing.T) {
	err := validateServiceTicketConfig(&Config{Auth: AuthConfig{
		ServiceTicketTTLSeconds: 300,
		ServiceTicketIssuer:     "paigram-account-center",
		ServiceTicketSigningKey: "short-key",
	}})
	require.Error(t, err)
}

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

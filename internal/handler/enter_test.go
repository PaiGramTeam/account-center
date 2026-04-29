package handler

import (
	"testing"

	"github.com/stretchr/testify/require"

	"paigram/internal/casbin"
	"paigram/internal/config"
	"paigram/internal/sessioncache"
)

func TestInitializeApiGroupsReturnsCasbinInitError(t *testing.T) {
	casbin.Reset()
	t.Cleanup(casbin.Reset)

	err := InitializeApiGroups(nil, sessioncache.NewNoopStore(), config.AuthConfig{}, config.SecurityConfig{})
	require.Error(t, err)
}

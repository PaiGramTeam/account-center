package handler_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDirectLegacyHandlerPackagesRemoved(t *testing.T) {
	for _, rel := range []string{
		"role",
		"permission",
		"session",
		"userrole",
		"botauth",
	} {
		_, err := os.Stat(filepath.Join(".", rel))
		require.ErrorIs(t, err, os.ErrNotExist, "%s should be removed", rel)
	}
}

func TestOverlappedLegacyHandlerPackagesRemoved(t *testing.T) {
	for _, rel := range []string{
		"profile",
		"security",
	} {
		_, err := os.Stat(filepath.Join(".", rel))
		require.ErrorIs(t, err, os.ErrNotExist, "%s should be removed", rel)
	}
}

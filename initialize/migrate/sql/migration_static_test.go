package sql

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMigration000044MapsLegacyGrantsThroughBindings(t *testing.T) {
	migration := readLocalMigrationForStaticTest(t, "000044_add_scopes_json_to_consumer_grants.up.sql")
	normalized := normalizeSQLForStaticTest(migration)

	require.NotRegexp(t, regexp.MustCompile(`(?i)SET\s+@BACKFILL_CONSUMER_GRANT_SCOPES_SQL\s*:=\s*IF\([^;]*BG\.PLATFORM_ACCOUNT_REF_ID\s*=\s*CG\.BINDING_ID`), normalized)
	require.NotRegexp(t, regexp.MustCompile(`(?i)SELECT\s+BG\.PLATFORM_ACCOUNT_REF_ID\s*,`), normalized)
	require.NotRegexp(t, regexp.MustCompile(`(?i)CG\.BINDING_ID\s*=\s*BG\.PLATFORM_ACCOUNT_REF_ID`), normalized)

	require.Contains(t, normalized, "JOIN PLATFORM_ACCOUNT_REFS PAR ON PAR.ID = BG.PLATFORM_ACCOUNT_REF_ID")
	require.Contains(t, normalized, "JOIN PLATFORM_ACCOUNT_BINDINGS PAB ON PAB.PLATFORM = PAR.PLATFORM")
	require.Contains(t, normalized, "PAB.PLATFORM_SERVICE_KEY = PAR.PLATFORM_SERVICE_KEY")
	require.Contains(t, normalized, "PAB.EXTERNAL_ACCOUNT_KEY = PAR.PLATFORM_ACCOUNT_ID")
	require.Contains(t, normalized, "PAR.USER_ID = PAB.OWNER_USER_ID")
	require.Contains(t, normalized, "PAR.DELETED_AT IS NULL")
	require.Contains(t, normalized, "PAB.DELETED_AT IS NULL")
	require.Contains(t, normalized, "PAB.STATUS = ''ACTIVE''")
	require.Contains(t, normalized, "ROW_NUMBER() OVER (PARTITION BY PAB.ID")
	require.Contains(t, normalized, "ORDER BY BG.UPDATED_AT DESC, BG.ID DESC")
	require.Contains(t, normalized, "WHERE RN = 1")
	require.Contains(t, normalized, "CG.STATUS = LEGACY.STATUS")
	require.Contains(t, normalized, "CG.REVOKED_AT = LEGACY.REVOKED_AT")
	require.Contains(t, normalized, "END <> ''''")
	require.Contains(t, normalized, "CG.BINDING_ID = LEGACY.BINDING_ID")
	require.Contains(t, normalized, "SELECT PAB.ID")
}

func readLocalMigrationForStaticTest(t *testing.T, name string) string {
	t.Helper()

	contents, err := os.ReadFile(name)
	require.NoError(t, err)
	return strings.ToUpper(string(contents))
}

func normalizeSQLForStaticTest(sql string) string {
	normalized := strings.NewReplacer("`", "", "\"", "").Replace(sql)
	return strings.Join(strings.Fields(normalized), " ")
}

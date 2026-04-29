//go:build integration

package integration

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMigrationsApplyToFreshMySQL(t *testing.T) {
	stack := newIntegrationStack(t)

	requireTableExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "schema_migrations")
	requireTableExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "users")
	requireTableExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "user_profiles")
	requireTableExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "user_emails")
	requireTableExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "user_sessions")
	requireTableExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "user_devices")
	requireTableExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "bot_identities")
	requireTableExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "platform_account_refs")
	requireTableExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "bot_account_grants")
	requireTableExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "platform_services")

	runMigrations(t, stack.SQLDB, stack.DatabaseCfg)
}

func TestUnifiedUserPlatformSchema(t *testing.T) {
	stack := newIntegrationStack(t)

	requireColumnExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "users", "primary_role_id")
	requireTableExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "platform_account_bindings")
	requireTableExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "platform_account_profiles")
	requireTableExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "consumer_grants")
	requireColumnExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "platform_account_bindings", "active_external_account_marker")
	requireColumnExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "platform_account_profiles", "primary_profile_marker")

	requireIndexExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "users", "idx_users_primary_role_id")
	requireIndexExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "platform_account_bindings", "uk_platform_account_bindings_active_external_account")
	requireIndexExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "platform_account_profiles", "uk_platform_account_profiles_primary_per_binding")
	requireForeignKeyExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "users", "fk_users_primary_role_assignment")
	requireForeignKeyExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "platform_account_bindings", "fk_platform_account_bindings_owner")
	requireForeignKeyExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "platform_account_bindings", "fk_platform_account_bindings_primary_profile")
	requireForeignKeyExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "platform_account_profiles", "fk_platform_account_profiles_binding")
	requireForeignKeyExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "consumer_grants", "fk_consumer_grants_binding")
	requireForeignKeyExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "consumer_grants", "fk_consumer_grants_granted_by")

	runMigrations(t, stack.SQLDB, stack.DatabaseCfg)
}

func TestUnifiedUserPlatformSchemaConstraints(t *testing.T) {
	stack := newIntegrationStack(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ownerOneID := insertTestUser(t, ctx, stack.SQLDB)
	ownerTwoID := insertTestUser(t, ctx, stack.SQLDB)

	bindingOneID := insertTestBinding(t, ctx, stack.SQLDB, ownerOneID, "mihomo", "cn:1001")
	_, err := stack.SQLDB.ExecContext(ctx, `
		INSERT INTO platform_account_bindings (owner_user_id, platform, external_account_key, platform_service_key, display_name)
		VALUES (?, ?, ?, 'mihomo', 'Duplicate Active Binding')
	`, ownerTwoID, "mihomo", "cn:1001")
	require.Error(t, err, "expected duplicate active binding to be rejected")

	_, err = stack.SQLDB.ExecContext(ctx, `
		UPDATE platform_account_bindings
		SET deleted_at = CURRENT_TIMESTAMP(3)
		WHERE id = ?
	`, bindingOneID)
	require.NoError(t, err)

	recreatedBindingID := insertTestBinding(t, ctx, stack.SQLDB, ownerTwoID, "mihomo", "cn:1001")
	require.NotZero(t, recreatedBindingID, "expected soft-deleted binding to be recreatable")

	primaryProfileID := insertTestProfile(t, ctx, stack.SQLDB, recreatedBindingID, "profile:1", true)
	_, err = stack.SQLDB.ExecContext(ctx, `
		INSERT INTO platform_account_profiles (binding_id, platform_profile_key, game_biz, region, player_uid, nickname, is_primary)
		VALUES (?, 'profile:2', 'hk4e_cn', 'cn_gf01', '10002', 'Second Primary', TRUE)
	`, recreatedBindingID)
	require.Error(t, err, "expected only one primary profile per binding")

	_, err = stack.SQLDB.ExecContext(ctx, `
		UPDATE platform_account_bindings
		SET primary_profile_id = ?
		WHERE id = ?
	`, primaryProfileID, recreatedBindingID)
	require.NoError(t, err, "expected binding to accept its own profile as primary")

	otherBindingID := insertTestBinding(t, ctx, stack.SQLDB, ownerOneID, "mihomo", "cn:2002")
	_, err = stack.SQLDB.ExecContext(ctx, `
		UPDATE platform_account_bindings
		SET primary_profile_id = ?
		WHERE id = ?
	`, primaryProfileID, otherBindingID)
	require.Error(t, err, "expected binding to reject another binding's profile")
}

func TestIdentityCredentialUniqueIndexesExist(t *testing.T) {
	stack := newIntegrationStack(t)

	requireIndexExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "user_credentials", "uniq_provider_account")
	requireIndexExists(t, stack.SQLDB, stack.DatabaseCfg.Dbname, "user_credentials", "uniq_user_provider")
}

func insertTestUser(t *testing.T, ctx context.Context, db *sql.DB) uint64 {
	t.Helper()

	result, err := db.ExecContext(ctx, `INSERT INTO users () VALUES ()`)
	require.NoError(t, err)

	id, err := result.LastInsertId()
	require.NoError(t, err)
	return uint64(id)
}

func insertTestBinding(t *testing.T, ctx context.Context, db *sql.DB, ownerUserID uint64, platform, externalAccountKey string) uint64 {
	t.Helper()

	result, err := db.ExecContext(ctx, `
		INSERT INTO platform_account_bindings (owner_user_id, platform, external_account_key, platform_service_key, display_name)
		VALUES (?, ?, ?, 'mihomo', 'Binding')
	`, ownerUserID, platform, externalAccountKey)
	require.NoError(t, err)

	id, err := result.LastInsertId()
	require.NoError(t, err)
	return uint64(id)
}

func insertTestProfile(t *testing.T, ctx context.Context, db *sql.DB, bindingID uint64, profileKey string, isPrimary bool) uint64 {
	t.Helper()

	result, err := db.ExecContext(ctx, `
		INSERT INTO platform_account_profiles (binding_id, platform_profile_key, game_biz, region, player_uid, nickname, is_primary)
		VALUES (?, ?, 'hk4e_cn', 'cn_gf01', '10001', 'Primary Profile', ?)
	`, bindingID, profileKey, isPrimary)
	require.NoError(t, err)

	id, err := result.LastInsertId()
	require.NoError(t, err)
	return uint64(id)
}

func requireColumnExists(t *testing.T, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, schema, table, column string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var count int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM information_schema.columns
		WHERE table_schema = ? AND table_name = ? AND column_name = ?
	`, schema, table, column).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count, "expected column %s.%s to exist", table, column)
}

func requireIndexExists(t *testing.T, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, schema, table, index string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var count int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM information_schema.statistics
		WHERE table_schema = ? AND table_name = ? AND index_name = ?
	`, schema, table, index).Scan(&count)
	require.NoError(t, err)
	require.Greater(t, count, 0, "expected index %s on %s to exist", index, table)
}

func requireForeignKeyExists(t *testing.T, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, schema, table, constraint string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var count int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM information_schema.table_constraints
		WHERE table_schema = ? AND table_name = ? AND constraint_name = ? AND constraint_type = 'FOREIGN KEY'
	`, schema, table, constraint).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count, "expected foreign key %s on %s to exist", constraint, table)
}

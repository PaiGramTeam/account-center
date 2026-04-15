//go:build integration

package integration

import "testing"

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

	runMigrations(t, stack.SQLDB, stack.DatabaseCfg)
}

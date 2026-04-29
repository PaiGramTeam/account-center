-- 1.0 release initial schema rollback.
--
-- Drops all tables created by the 1.0 init migration. Order matters because of
-- foreign keys; we drop dependent tables before their parents and remove the
-- circular FK on users before dropping user_roles.

ALTER TABLE platform_account_bindings DROP FOREIGN KEY fk_platform_account_bindings_primary_profile;
ALTER TABLE users DROP FOREIGN KEY fk_users_primary_role_assignment;

DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS legal_documents;
DROP TABLE IF EXISTS system_config_entries;
DROP TABLE IF EXISTS consumer_grants;
DROP TABLE IF EXISTS platform_account_profiles;
DROP TABLE IF EXISTS platform_account_bindings;
DROP TABLE IF EXISTS bot_account_grants;
DROP TABLE IF EXISTS platform_account_refs;
DROP TABLE IF EXISTS platform_services;
DROP TABLE IF EXISTS bot_identities;
DROP TABLE IF EXISTS bot_tokens;
DROP TABLE IF EXISTS bots;
DROP TABLE IF EXISTS casbin_rule;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS login_logs;
DROP TABLE IF EXISTS user_devices;
DROP TABLE IF EXISTS user_two_factors;
DROP TABLE IF EXISTS login_audits;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS user_oauth_states;
DROP TABLE IF EXISTS user_emails;
DROP TABLE IF EXISTS user_credentials;
DROP TABLE IF EXISTS user_profiles;
DROP TABLE IF EXISTS users;

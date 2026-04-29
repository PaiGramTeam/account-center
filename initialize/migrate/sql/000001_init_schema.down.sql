-- 1.0 release schema rollback.
-- Drops all tables in reverse dependency order.

SET FOREIGN_KEY_CHECKS = 0;

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

SET FOREIGN_KEY_CHECKS = 1;
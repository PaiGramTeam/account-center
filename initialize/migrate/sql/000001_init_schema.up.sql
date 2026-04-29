-- 1.0 release initial schema.
--
-- This migration consolidates all pre-1.0 incremental migrations into a single
-- initial schema definition. It is intentionally the only migration file in the
-- repository. Future schema changes must be added as new numbered migrations on
-- top of this file.

-- -----------------------------------------------------------------------------
-- Identity & users
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    primary_login_type VARCHAR(32) NOT NULL DEFAULT 'email',
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    primary_role_id BIGINT UNSIGNED NULL,
    last_login_at DATETIME(3) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    KEY idx_users_status (status),
    KEY idx_users_primary_role_id (primary_role_id),
    KEY idx_users_primary_role_assignment (id, primary_role_id),
    KEY idx_users_last_login_at (last_login_at),
    KEY idx_users_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_profiles (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    avatar_url VARCHAR(512) NULL,
    bio TEXT NULL,
    locale VARCHAR(10) NOT NULL DEFAULT 'en_US',
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    CONSTRAINT fk_user_profiles_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_credentials (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    provider VARCHAR(64) NOT NULL,
    provider_account_id VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NULL,
    access_token TEXT NULL COMMENT 'AES-256-GCM encrypted OAuth access token',
    refresh_token TEXT NULL COMMENT 'AES-256-GCM encrypted OAuth refresh token',
    token_expiry DATETIME(3) NULL,
    scopes VARCHAR(512) NULL,
    last_sync_at DATETIME(3) NULL,
    metadata TEXT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY uniq_provider_account (provider, provider_account_id),
    UNIQUE KEY uniq_user_provider (user_id, provider),
    KEY idx_user_credentials_provider_user (provider, user_id),
    CONSTRAINT fk_user_credentials_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_emails (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    email VARCHAR(255) NOT NULL,
    is_primary TINYINT(1) NOT NULL DEFAULT 0,
    verified_at DATETIME(3) NULL,
    verification_token VARCHAR(255) NULL,
    verification_expiry DATETIME(3) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY uniq_email (email),
    KEY idx_user_primary (user_id, is_primary),
    KEY idx_verification_token (verification_token),
    CONSTRAINT fk_user_emails_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_oauth_states (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    provider VARCHAR(64) NOT NULL,
    state VARCHAR(255) NOT NULL,
    purpose VARCHAR(64) NOT NULL DEFAULT 'login',
    user_id BIGINT UNSIGNED NULL,
    redirect_to VARCHAR(512) NULL,
    nonce VARCHAR(255) NULL,
    code_verifier VARCHAR(255) NULL COMMENT 'PKCE code verifier for secure authorization code exchange',
    expires_at DATETIME(3) NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE KEY uniq_state (state),
    KEY idx_provider_expires (provider, expires_at),
    KEY idx_oauth_state_code_verifier (code_verifier),
    KEY idx_user_oauth_states_purpose (purpose),
    KEY idx_user_oauth_states_user_id (user_id),
    CONSTRAINT fk_user_oauth_states_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_sessions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    access_token_hash VARCHAR(64) NOT NULL,
    refresh_token_hash VARCHAR(64) NOT NULL,
    access_expiry DATETIME(3) NOT NULL,
    refresh_expiry DATETIME(3) NOT NULL,
    user_agent VARCHAR(512) NULL,
    client_ip VARCHAR(128) NULL,
    revoked_at DATETIME(3) NULL,
    revoked_reason VARCHAR(255) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY uniq_access_token_hash (access_token_hash),
    UNIQUE KEY uniq_refresh_token_hash (refresh_token_hash),
    KEY idx_user_sessions_user (user_id),
    KEY idx_refresh_expiry (refresh_expiry),
    KEY idx_access_expiry (access_expiry),
    CONSTRAINT fk_user_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS login_audits (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NULL,
    provider VARCHAR(64) NOT NULL,
    success TINYINT(1) NOT NULL,
    client_ip VARCHAR(128) NULL,
    user_agent VARCHAR(512) NULL,
    message VARCHAR(512) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    KEY idx_login_audits_user (user_id),
    KEY idx_login_audits_provider (provider)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_two_factors (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    secret VARCHAR(255) NOT NULL COMMENT 'Encrypted TOTP secret',
    backup_codes TEXT COMMENT 'JSON array of encrypted backup codes',
    enabled_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_used_at DATETIME(3),
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY uk_user_id (user_id),
    KEY idx_two_factor_enabled_at (enabled_at),
    CONSTRAINT fk_user_two_factor_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_devices (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    device_id VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    device_type VARCHAR(64) COMMENT 'mobile, desktop, tablet, etc.',
    os VARCHAR(64),
    browser VARCHAR(64),
    ip VARCHAR(128),
    location VARCHAR(255) COMMENT 'City, Country',
    last_active_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    trust_expiry DATETIME(3) COMMENT 'For trusted device feature',
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY uk_device_id (device_id),
    KEY idx_user_devices (user_id),
    KEY idx_last_active (last_active_at),
    CONSTRAINT fk_user_device_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS login_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    login_type VARCHAR(32) NOT NULL,
    ip VARCHAR(128),
    user_agent VARCHAR(512),
    device VARCHAR(255),
    location VARCHAR(255),
    status VARCHAR(32) NOT NULL COMMENT 'success, failed',
    failure_reason VARCHAR(255),
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    KEY idx_user_login_logs (user_id, created_at),
    KEY idx_login_type (login_type),
    KEY idx_login_logs_status (status),
    KEY idx_login_logs_created_at (created_at),
    CONSTRAINT fk_login_log_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    action VARCHAR(128) NOT NULL,
    resource VARCHAR(128),
    resource_id BIGINT UNSIGNED,
    old_value TEXT,
    new_value TEXT,
    ip VARCHAR(128),
    user_agent VARCHAR(512),
    details TEXT COMMENT 'JSON details',
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    KEY idx_user_audit_logs (user_id, created_at),
    KEY idx_audit_logs_action (action),
    KEY idx_audit_logs_resource (resource_id),
    KEY idx_audit_logs_created_at (created_at),
    CONSTRAINT fk_audit_log_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    token VARCHAR(255) NOT NULL,
    expires_at DATETIME(3) NOT NULL,
    used_at DATETIME(3),
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE KEY uk_token (token),
    KEY idx_user_password_reset (user_id),
    KEY idx_password_reset_expires_at (expires_at),
    CONSTRAINT fk_password_reset_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- Authority (roles, permissions, casbin)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS permissions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE COMMENT 'Unique permission identifier (e.g., user:create)',
    resource VARCHAR(100) NOT NULL COMMENT 'Resource type (e.g., user, role, bot)',
    action VARCHAR(50) NOT NULL COMMENT 'Action type (e.g., create, read, update, delete)',
    description VARCHAR(512) COMMENT 'Human-readable description',
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    KEY idx_permissions_resource (resource),
    KEY idx_permissions_action (action),
    KEY idx_permissions_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS roles (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE COMMENT 'Unique role identifier (e.g., admin, moderator)',
    display_name VARCHAR(255) NOT NULL COMMENT 'Human-readable role name',
    description VARCHAR(512) COMMENT 'Role description',
    is_system BOOLEAN NOT NULL DEFAULT FALSE COMMENT 'System roles cannot be deleted',
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    KEY idx_roles_is_system (is_system),
    KEY idx_roles_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id BIGINT UNSIGNED NOT NULL,
    permission_id BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (role_id, permission_id),
    KEY idx_role_permission (role_id, permission_id),
    CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_roles (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    role_id BIGINT UNSIGNED NOT NULL,
    granted_by BIGINT UNSIGNED COMMENT 'User ID who granted this role',
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY idx_user_role (user_id, role_id),
    KEY idx_user_roles_user_id (user_id),
    KEY idx_user_roles_role_id (role_id),
    KEY idx_user_roles_granted_by (granted_by),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- users.primary_role_id closes the cycle with user_roles. We must add the FK
-- after both tables exist.
ALTER TABLE users
    ADD CONSTRAINT fk_users_primary_role_assignment
        FOREIGN KEY (id, primary_role_id) REFERENCES user_roles (user_id, role_id)
        ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE TABLE IF NOT EXISTS casbin_rule (
    id bigint unsigned NOT NULL AUTO_INCREMENT,
    ptype varchar(100) DEFAULT NULL,
    v0 varchar(100) DEFAULT NULL,
    v1 varchar(100) DEFAULT NULL,
    v2 varchar(100) DEFAULT NULL,
    v3 varchar(100) DEFAULT NULL,
    v4 varchar(100) DEFAULT NULL,
    v5 varchar(100) DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY idx_casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Casbin policy rules';

-- -----------------------------------------------------------------------------
-- Bots & bot identities
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS bots (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT NULL,
    type VARCHAR(32) NOT NULL DEFAULT 'OTHER',
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    allow_legacy_binding_write BOOLEAN NOT NULL DEFAULT FALSE,
    owner_user_id BIGINT UNSIGNED NOT NULL,
    api_key VARCHAR(255) NOT NULL,
    api_secret VARCHAR(512) NOT NULL,
    scopes VARCHAR(1024) DEFAULT '[]',
    metadata JSON NULL COMMENT 'Custom metadata (e.g., subscription plan, client version)',
    last_active_at DATETIME(3) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    UNIQUE KEY uniq_api_key (api_key),
    KEY idx_owner_user (owner_user_id),
    KEY idx_bots_status (status),
    KEY idx_bots_deleted_at (deleted_at),
    CONSTRAINT fk_bots_owner FOREIGN KEY (owner_user_id) REFERENCES users (id) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS bot_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    bot_id VARCHAR(64) NOT NULL,
    access_token_hash VARCHAR(64) NOT NULL,
    refresh_token_hash VARCHAR(64) NOT NULL,
    rate_limit_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rate_limit_time_window BIGINT NULL COMMENT 'Time window in milliseconds',
    rate_limit_max INT NULL COMMENT 'Max requests within time window',
    request_count INT NOT NULL DEFAULT 0,
    last_request DATETIME(3) NULL,
    metadata JSON NULL COMMENT 'Custom metadata for this token',
    expires_at DATETIME(3) NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    revoked_at DATETIME(3) NULL,
    UNIQUE KEY uniq_access_token_hash (access_token_hash),
    UNIQUE KEY uniq_refresh_token_hash (refresh_token_hash),
    KEY idx_bot_id (bot_id),
    KEY idx_bot_tokens_expires_at (expires_at),
    KEY idx_last_request (last_request),
    CONSTRAINT fk_bot_tokens_bot FOREIGN KEY (bot_id) REFERENCES bots (id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS bot_identities (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    bot_id VARCHAR(64) NOT NULL,
    external_user_id VARCHAR(191) NOT NULL,
    external_username VARCHAR(255) NULL,
    linked_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_bot_identities_bot_external (bot_id, external_user_id),
    UNIQUE KEY uk_bot_identities_user_bot (user_id, bot_id),
    KEY idx_bot_identities_user_id (user_id),
    KEY idx_bot_identities_deleted_at (deleted_at),
    CONSTRAINT fk_bot_identities_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_bot_identities_bot FOREIGN KEY (bot_id) REFERENCES bots (id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Bot external user identity mapping';

-- -----------------------------------------------------------------------------
-- Platform services & legacy account refs
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS platform_services (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    platform_key VARCHAR(64) NOT NULL,
    display_name VARCHAR(128) NOT NULL,
    service_key VARCHAR(128) NOT NULL,
    service_audience VARCHAR(128) NOT NULL,
    discovery_type VARCHAR(32) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    supported_actions_json JSON NOT NULL,
    credential_schema_json JSON NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uniq_platform_services_platform_key (platform_key),
    UNIQUE KEY uniq_platform_services_service_key (service_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Platform service registry';

CREATE TABLE IF NOT EXISTS platform_account_refs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    platform VARCHAR(64) NOT NULL,
    platform_service_key VARCHAR(128) NOT NULL,
    platform_account_id VARCHAR(191) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    meta_json JSON NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_platform_account_refs_platform_account (platform, platform_account_id),
    KEY idx_platform_account_refs_user_platform (user_id, platform),
    KEY idx_platform_account_refs_status (status),
    KEY idx_platform_account_refs_deleted_at (deleted_at),
    CONSTRAINT fk_platform_account_refs_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Legacy platform account references';

CREATE TABLE IF NOT EXISTS bot_account_grants (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    bot_id VARCHAR(64) NOT NULL,
    platform_account_ref_id BIGINT UNSIGNED NOT NULL,
    scopes JSON NOT NULL,
    granted_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    revoked_at DATETIME(3) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_bot_account_grants_bot_account (bot_id, platform_account_ref_id),
    KEY idx_bot_account_grants_user_id (user_id),
    KEY idx_bot_account_grants_platform_account_ref_id (platform_account_ref_id),
    KEY idx_bot_account_grants_revoked_at (revoked_at),
    KEY idx_bot_account_grants_deleted_at (deleted_at),
    CONSTRAINT fk_bot_account_grants_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_bot_account_grants_bot FOREIGN KEY (bot_id) REFERENCES bots (id) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_bot_account_grants_ref FOREIGN KEY (platform_account_ref_id) REFERENCES platform_account_refs (id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Legacy bot grants over platform account references';

-- -----------------------------------------------------------------------------
-- Unified platform account bindings, profiles and consumer grants
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS platform_account_bindings (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    owner_user_id BIGINT UNSIGNED NOT NULL,
    platform VARCHAR(64) NOT NULL,
    external_account_key VARCHAR(191) NULL,
    platform_service_key VARCHAR(128) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending_bind',
    status_reason_code VARCHAR(64) NULL,
    status_reason_message VARCHAR(255) NULL,
    primary_profile_id BIGINT UNSIGNED NULL,
    last_validated_at DATETIME(3) NULL,
    last_synced_at DATETIME(3) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    active_external_account_marker TINYINT GENERATED ALWAYS AS (IF(deleted_at IS NULL AND external_account_key IS NOT NULL, 1, NULL)) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uk_platform_account_bindings_active_external_account (platform, external_account_key, active_external_account_marker),
    KEY idx_platform_account_bindings_owner (owner_user_id),
    KEY idx_platform_account_bindings_status (status),
    KEY idx_platform_account_bindings_primary_profile_id (primary_profile_id),
    KEY idx_platform_account_bindings_primary_profile_assignment (id, primary_profile_id),
    KEY idx_platform_account_bindings_deleted_at (deleted_at),
    CONSTRAINT fk_platform_account_bindings_owner FOREIGN KEY (owner_user_id) REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Unified platform account ownership bindings';

CREATE TABLE IF NOT EXISTS platform_account_profiles (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    binding_id BIGINT UNSIGNED NOT NULL,
    platform_profile_key VARCHAR(191) NOT NULL,
    game_biz VARCHAR(64) NOT NULL,
    region VARCHAR(64) NOT NULL,
    player_uid VARCHAR(64) NOT NULL,
    nickname VARCHAR(255) NOT NULL,
    level BIGINT NULL,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    source_updated_at DATETIME(3) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    primary_profile_marker TINYINT GENERATED ALWAYS AS (IF(is_primary, 1, NULL)) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uk_platform_account_profiles_binding_key (binding_id, platform_profile_key),
    UNIQUE KEY uk_platform_account_profiles_primary_per_binding (binding_id, primary_profile_marker),
    UNIQUE KEY uk_platform_account_profiles_binding_row (binding_id, id),
    KEY idx_platform_account_profiles_binding_id (binding_id),
    KEY idx_platform_account_profiles_player_uid (player_uid),
    CONSTRAINT fk_platform_account_profiles_binding FOREIGN KEY (binding_id) REFERENCES platform_account_bindings (id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Projected profiles discovered under a platform account binding';

ALTER TABLE platform_account_bindings
    ADD CONSTRAINT fk_platform_account_bindings_primary_profile
        FOREIGN KEY (id, primary_profile_id) REFERENCES platform_account_profiles (binding_id, id)
        ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE TABLE IF NOT EXISTS consumer_grants (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    binding_id BIGINT UNSIGNED NOT NULL,
    consumer VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    scopes_json LONGTEXT NOT NULL,
    ticket_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    granted_by BIGINT UNSIGNED NULL,
    granted_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    revoked_at DATETIME(3) NULL,
    last_invalidated_at DATETIME(3) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uk_consumer_grants_binding_consumer (binding_id, consumer),
    KEY idx_consumer_grants_binding_id (binding_id),
    KEY idx_consumer_grants_status (status),
    KEY idx_consumer_grants_granted_by (granted_by),
    CONSTRAINT fk_consumer_grants_binding FOREIGN KEY (binding_id) REFERENCES platform_account_bindings (id) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_consumer_grants_granted_by FOREIGN KEY (granted_by) REFERENCES users (id) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Consumer access grants for platform account bindings';

-- -----------------------------------------------------------------------------
-- System config, legal documents, audit events
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS system_config_entries (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    config_domain VARCHAR(64) NOT NULL,
    payload_json JSON NOT NULL,
    version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    updated_by BIGINT UNSIGNED NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    UNIQUE KEY uk_system_config_entries_domain (config_domain),
    KEY idx_system_config_entries_updated_by (updated_by),
    KEY idx_system_config_entries_deleted_at (deleted_at),
    CONSTRAINT fk_system_config_entries_updated_by FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS legal_documents (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    document_type VARCHAR(32) NOT NULL,
    version VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    content LONGTEXT NOT NULL,
    published BOOLEAN NOT NULL DEFAULT FALSE,
    published_at DATETIME(3) NULL,
    updated_by BIGINT UNSIGNED NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    UNIQUE KEY uk_legal_document_type_version (document_type, version),
    KEY idx_legal_documents_published (published),
    KEY idx_legal_documents_updated_by (updated_by),
    KEY idx_legal_documents_deleted_at (deleted_at),
    CONSTRAINT fk_legal_documents_updated_by FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    category VARCHAR(64) NOT NULL,
    actor_type VARCHAR(32) NOT NULL,
    actor_user_id BIGINT UNSIGNED NULL,
    action VARCHAR(128) NOT NULL,
    target_type VARCHAR(64) NULL,
    target_id VARCHAR(191) NULL,
    binding_id BIGINT UNSIGNED NULL,
    result VARCHAR(32) NOT NULL,
    reason_code VARCHAR(64) NULL,
    request_id VARCHAR(128) NULL,
    ip VARCHAR(128) NULL,
    user_agent VARCHAR(512) NULL,
    metadata_json JSON NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    KEY idx_audit_events_category (category),
    KEY idx_audit_events_actor_type (actor_type),
    KEY idx_audit_events_actor_user_id (actor_user_id),
    KEY idx_audit_events_action (action),
    KEY idx_audit_events_target_type (target_type),
    KEY idx_audit_events_target_id (target_id),
    KEY idx_audit_events_binding_id (binding_id),
    KEY idx_audit_events_result (result),
    KEY idx_audit_events_reason_code (reason_code),
    KEY idx_audit_events_request_id (request_id),
    KEY idx_audit_events_created_at (created_at),
    CONSTRAINT fk_audit_events_actor_user FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_audit_events_binding FOREIGN KEY (binding_id) REFERENCES platform_account_bindings(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

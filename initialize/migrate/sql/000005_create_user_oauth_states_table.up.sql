CREATE TABLE IF NOT EXISTS user_oauth_states (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    provider VARCHAR(64) NOT NULL,
    state VARCHAR(255) NOT NULL,
    redirect_to VARCHAR(512) NULL,
    nonce VARCHAR(255) NULL,
    expires_at DATETIME(3) NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE KEY uniq_state (state),
    KEY idx_provider_expires (provider, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
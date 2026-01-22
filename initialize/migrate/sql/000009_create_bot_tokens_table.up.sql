CREATE TABLE IF NOT EXISTS bot_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    bot_id VARCHAR(64) NOT NULL,
    access_token VARCHAR(512) NOT NULL,
    refresh_token VARCHAR(512) NOT NULL,
    expires_at DATETIME(3) NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    revoked_at DATETIME(3) NULL,
    UNIQUE KEY uniq_access_token (access_token),
    UNIQUE KEY uniq_refresh_token (refresh_token),
    KEY idx_bot_id (bot_id),
    KEY idx_expires_at (expires_at),
    CONSTRAINT fk_bot_tokens_bot FOREIGN KEY (bot_id) REFERENCES bots (id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
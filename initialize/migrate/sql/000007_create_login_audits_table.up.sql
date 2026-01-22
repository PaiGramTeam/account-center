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
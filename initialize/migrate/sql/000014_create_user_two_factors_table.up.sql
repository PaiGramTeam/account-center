-- Create user two factor authentication table
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
-- Create user devices table
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
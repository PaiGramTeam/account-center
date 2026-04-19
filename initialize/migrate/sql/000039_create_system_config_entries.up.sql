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

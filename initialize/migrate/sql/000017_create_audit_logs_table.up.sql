-- Create audit logs table
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
    KEY idx_action (action),
    KEY idx_resource (resource_id),
    KEY idx_created_at (created_at),
    CONSTRAINT fk_audit_log_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
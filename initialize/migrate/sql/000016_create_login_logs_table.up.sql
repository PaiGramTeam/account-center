-- Create login logs table
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
    KEY idx_status (status),
    KEY idx_created_at (created_at),
    CONSTRAINT fk_login_log_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
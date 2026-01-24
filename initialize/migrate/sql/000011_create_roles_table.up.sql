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

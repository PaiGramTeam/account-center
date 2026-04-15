CREATE TABLE IF NOT EXISTS `platform_account_refs` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `platform` VARCHAR(64) NOT NULL,
    `platform_service_key` VARCHAR(128) NOT NULL,
    `platform_account_id` VARCHAR(191) NOT NULL,
    `display_name` VARCHAR(255) NOT NULL,
    `status` VARCHAR(32) NOT NULL DEFAULT 'active',
    `meta_json` JSON NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    `deleted_at` DATETIME(3) NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_platform_account_refs_platform_account` (`platform`, `platform_account_id`),
    KEY `idx_platform_account_refs_user_platform` (`user_id`, `platform`),
    KEY `idx_platform_account_refs_status` (`status`),
    KEY `idx_platform_account_refs_deleted_at` (`deleted_at`),
    CONSTRAINT `fk_platform_account_refs_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='平台账号引用表';

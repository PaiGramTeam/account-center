CREATE TABLE IF NOT EXISTS `bot_identities` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` BIGINT UNSIGNED NOT NULL,
    `bot_id` VARCHAR(64) NOT NULL,
    `external_user_id` VARCHAR(191) NOT NULL,
    `external_username` VARCHAR(255) NULL,
    `linked_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    `deleted_at` DATETIME(3) NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_bot_identities_bot_external` (`bot_id`, `external_user_id`),
    UNIQUE KEY `uk_bot_identities_user_bot` (`user_id`, `bot_id`),
    KEY `idx_bot_identities_user_id` (`user_id`),
    KEY `idx_bot_identities_deleted_at` (`deleted_at`),
    CONSTRAINT `fk_bot_identities_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT `fk_bot_identities_bot` FOREIGN KEY (`bot_id`) REFERENCES `bots` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Bot 外部用户身份映射表';

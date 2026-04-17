CREATE TABLE IF NOT EXISTS `platform_account_profiles` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `binding_id` BIGINT UNSIGNED NOT NULL,
    `platform_profile_key` VARCHAR(191) NOT NULL,
    `game_biz` VARCHAR(64) NOT NULL,
    `region` VARCHAR(64) NOT NULL,
    `player_uid` VARCHAR(64) NOT NULL,
    `nickname` VARCHAR(255) NOT NULL,
    `level` BIGINT NULL,
    `is_primary` BOOLEAN NOT NULL DEFAULT FALSE,
    `source_updated_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    `primary_profile_marker` TINYINT GENERATED ALWAYS AS (IF(`is_primary`, 1, NULL)) STORED,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_platform_account_profiles_binding_key` (`binding_id`, `platform_profile_key`),
    UNIQUE KEY `uk_platform_account_profiles_primary_per_binding` (`binding_id`, `primary_profile_marker`),
    UNIQUE KEY `uk_platform_account_profiles_binding_row` (`binding_id`, `id`),
    KEY `idx_platform_account_profiles_binding_id` (`binding_id`),
    KEY `idx_platform_account_profiles_player_uid` (`player_uid`),
    CONSTRAINT `fk_platform_account_profiles_binding` FOREIGN KEY (`binding_id`) REFERENCES `platform_account_bindings` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Projected profiles discovered under a platform account binding';

ALTER TABLE `platform_account_bindings`
    ADD CONSTRAINT `fk_platform_account_bindings_primary_profile`
        FOREIGN KEY (`id`, `primary_profile_id`) REFERENCES `platform_account_profiles` (`binding_id`, `id`)
        ON DELETE RESTRICT ON UPDATE CASCADE;

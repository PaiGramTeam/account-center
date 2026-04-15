CREATE TABLE IF NOT EXISTS `platform_services` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `platform_key` VARCHAR(64) NOT NULL,
    `display_name` VARCHAR(128) NOT NULL,
    `service_key` VARCHAR(128) NOT NULL,
    `service_audience` VARCHAR(128) NOT NULL,
    `discovery_type` VARCHAR(32) NOT NULL,
    `endpoint` VARCHAR(255) NOT NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT TRUE,
    `supported_actions_json` JSON NOT NULL,
    `credential_schema_json` JSON NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (`id`),
    UNIQUE KEY `uniq_platform_services_platform_key` (`platform_key`),
    UNIQUE KEY `uniq_platform_services_service_key` (`service_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='平台服务注册表';

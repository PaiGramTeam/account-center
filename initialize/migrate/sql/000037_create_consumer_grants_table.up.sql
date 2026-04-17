CREATE TABLE IF NOT EXISTS `consumer_grants` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `binding_id` BIGINT UNSIGNED NOT NULL,
    `consumer` VARCHAR(64) NOT NULL,
    `status` VARCHAR(32) NOT NULL DEFAULT 'active',
    `granted_by` BIGINT UNSIGNED NULL,
    `granted_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `revoked_at` DATETIME(3) NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_consumer_grants_binding_consumer` (`binding_id`, `consumer`),
    KEY `idx_consumer_grants_binding_id` (`binding_id`),
    KEY `idx_consumer_grants_status` (`status`),
    KEY `idx_consumer_grants_granted_by` (`granted_by`),
    CONSTRAINT `fk_consumer_grants_binding` FOREIGN KEY (`binding_id`) REFERENCES `platform_account_bindings` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT `fk_consumer_grants_granted_by` FOREIGN KEY (`granted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Consumer access grants for platform account bindings';

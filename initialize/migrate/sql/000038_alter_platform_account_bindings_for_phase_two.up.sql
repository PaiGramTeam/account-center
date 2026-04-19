ALTER TABLE `platform_account_bindings`
    DROP INDEX `uk_platform_account_bindings_active_external_account`;

ALTER TABLE `platform_account_bindings`
    MODIFY COLUMN `external_account_key` VARCHAR(191) NULL,
    DROP COLUMN `active_binding_marker`,
    ADD COLUMN `status_reason_code` VARCHAR(64) NULL AFTER `status`,
    ADD COLUMN `status_reason_message` VARCHAR(255) NULL AFTER `status_reason_code`,
    ADD COLUMN `last_validated_at` DATETIME(3) NULL AFTER `primary_profile_id`,
    ADD COLUMN `active_external_account_marker` TINYINT GENERATED ALWAYS AS (IF(`deleted_at` IS NULL AND `external_account_key` IS NOT NULL, 1, NULL)) STORED AFTER `deleted_at`;

ALTER TABLE `platform_account_bindings`
    ADD UNIQUE KEY `uk_platform_account_bindings_active_external_account` (`platform`, `external_account_key`, `active_external_account_marker`);

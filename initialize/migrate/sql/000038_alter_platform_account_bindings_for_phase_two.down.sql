ALTER TABLE `platform_account_bindings`
    DROP INDEX `uk_platform_account_bindings_active_external_account`;

UPDATE `platform_account_bindings`
SET `external_account_key` = CONCAT('__draft_rollback__:', `id`)
WHERE `external_account_key` IS NULL;

ALTER TABLE `platform_account_bindings`
    DROP COLUMN `active_external_account_marker`,
    DROP COLUMN `last_validated_at`,
    DROP COLUMN `status_reason_message`,
    DROP COLUMN `status_reason_code`,
    MODIFY COLUMN `external_account_key` VARCHAR(191) NOT NULL,
    ADD COLUMN `active_binding_marker` TINYINT GENERATED ALWAYS AS (IF(`deleted_at` IS NULL, 1, NULL)) STORED AFTER `deleted_at`;

ALTER TABLE `platform_account_bindings`
    ADD UNIQUE KEY `uk_platform_account_bindings_active_external_account` (`platform`, `external_account_key`, `active_binding_marker`);

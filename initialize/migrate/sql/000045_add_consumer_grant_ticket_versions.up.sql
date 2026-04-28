ALTER TABLE `consumer_grants`
    ADD COLUMN `ticket_version` BIGINT UNSIGNED NOT NULL DEFAULT 1 AFTER `scopes_json`,
    ADD COLUMN `last_invalidated_at` DATETIME(3) NULL AFTER `revoked_at`;

UPDATE `consumer_grants`
SET `ticket_version` = 2,
    `last_invalidated_at` = COALESCE(`revoked_at`, `updated_at`)
WHERE `status` = 'revoked' OR `revoked_at` IS NOT NULL;

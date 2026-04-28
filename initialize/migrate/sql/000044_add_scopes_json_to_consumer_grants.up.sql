ALTER TABLE `consumer_grants`
    ADD COLUMN `scopes_json` LONGTEXT NULL AFTER `status`;

SET @has_legacy_bot_account_grants := EXISTS(
    SELECT 1
    FROM information_schema.tables
    WHERE table_schema = DATABASE()
      AND table_name = 'bot_account_grants'
);

SET @backfill_consumer_grant_scopes_sql := IF(
    @has_legacy_bot_account_grants,
    'UPDATE `consumer_grants` cg JOIN (SELECT * FROM (SELECT pab.`id` AS `binding_id`, CASE WHEN bg.`bot_id` IN (''bot-paigram'', ''paigram-bot'') THEN ''paigram-bot'' WHEN bg.`bot_id` IN (''bot-pamgram'', ''pamgram'') THEN ''pamgram'' ELSE '''' END AS `consumer`, CASE WHEN bg.`revoked_at` IS NULL THEN ''active'' ELSE ''revoked'' END AS `status`, bg.`scopes`, bg.`revoked_at`, ROW_NUMBER() OVER (PARTITION BY pab.`id`, CASE WHEN bg.`bot_id` IN (''bot-paigram'', ''paigram-bot'') THEN ''paigram-bot'' WHEN bg.`bot_id` IN (''bot-pamgram'', ''pamgram'') THEN ''pamgram'' ELSE '''' END ORDER BY bg.`updated_at` DESC, bg.`id` DESC) AS `rn` FROM `bot_account_grants` bg JOIN `platform_account_refs` par ON par.`id` = bg.`platform_account_ref_id` JOIN `platform_account_bindings` pab ON pab.`platform` = par.`platform` AND pab.`platform_service_key` = par.`platform_service_key` AND pab.`external_account_key` = par.`platform_account_id` AND par.`user_id` = pab.`owner_user_id` WHERE bg.`deleted_at` IS NULL AND par.`deleted_at` IS NULL AND pab.`deleted_at` IS NULL AND pab.`status` = ''active'' AND CASE WHEN bg.`bot_id` IN (''bot-paigram'', ''paigram-bot'') THEN ''paigram-bot'' WHEN bg.`bot_id` IN (''bot-pamgram'', ''pamgram'') THEN ''pamgram'' ELSE '''' END <> '''') ranked_legacy_grants WHERE `rn` = 1) legacy ON cg.`binding_id` = legacy.`binding_id` AND cg.`consumer` = legacy.`consumer` SET cg.`scopes_json` = legacy.`scopes`, cg.`status` = legacy.`status`, cg.`revoked_at` = legacy.`revoked_at`',
    'SELECT 1'
);

PREPARE backfill_consumer_grant_scopes_stmt FROM @backfill_consumer_grant_scopes_sql;
EXECUTE backfill_consumer_grant_scopes_stmt;
DEALLOCATE PREPARE backfill_consumer_grant_scopes_stmt;

SET @insert_missing_consumer_grants_sql := IF(
    @has_legacy_bot_account_grants,
    'INSERT INTO `consumer_grants` (`binding_id`, `consumer`, `status`, `scopes_json`, `granted_at`, `revoked_at`, `created_at`, `updated_at`) SELECT legacy.`binding_id`, legacy.`consumer`, legacy.`status`, legacy.`scopes`, legacy.`granted_at`, legacy.`revoked_at`, legacy.`created_at`, legacy.`updated_at` FROM (SELECT * FROM (SELECT pab.`id` AS `binding_id`, CASE WHEN bg.`bot_id` IN (''bot-paigram'', ''paigram-bot'') THEN ''paigram-bot'' WHEN bg.`bot_id` IN (''bot-pamgram'', ''pamgram'') THEN ''pamgram'' ELSE '''' END AS `consumer`, CASE WHEN bg.`revoked_at` IS NULL THEN ''active'' ELSE ''revoked'' END AS `status`, bg.`scopes`, bg.`granted_at`, bg.`revoked_at`, bg.`created_at`, bg.`updated_at`, ROW_NUMBER() OVER (PARTITION BY pab.`id`, CASE WHEN bg.`bot_id` IN (''bot-paigram'', ''paigram-bot'') THEN ''paigram-bot'' WHEN bg.`bot_id` IN (''bot-pamgram'', ''pamgram'') THEN ''pamgram'' ELSE '''' END ORDER BY bg.`updated_at` DESC, bg.`id` DESC) AS `rn` FROM `bot_account_grants` bg JOIN `platform_account_refs` par ON par.`id` = bg.`platform_account_ref_id` JOIN `platform_account_bindings` pab ON pab.`platform` = par.`platform` AND pab.`platform_service_key` = par.`platform_service_key` AND pab.`external_account_key` = par.`platform_account_id` AND par.`user_id` = pab.`owner_user_id` WHERE bg.`deleted_at` IS NULL AND par.`deleted_at` IS NULL AND pab.`deleted_at` IS NULL AND pab.`status` = ''active'' AND CASE WHEN bg.`bot_id` IN (''bot-paigram'', ''paigram-bot'') THEN ''paigram-bot'' WHEN bg.`bot_id` IN (''bot-pamgram'', ''pamgram'') THEN ''pamgram'' ELSE '''' END <> '''') ranked_legacy_grants WHERE `rn` = 1) legacy LEFT JOIN `consumer_grants` cg ON cg.`binding_id` = legacy.`binding_id` AND cg.`consumer` = legacy.`consumer` WHERE cg.`id` IS NULL',
    'SELECT 1'
);

PREPARE insert_missing_consumer_grants_stmt FROM @insert_missing_consumer_grants_sql;
EXECUTE insert_missing_consumer_grants_stmt;
DEALLOCATE PREPARE insert_missing_consumer_grants_stmt;

UPDATE `consumer_grants`
SET `scopes_json` = '[]'
WHERE `scopes_json` IS NULL;

ALTER TABLE `consumer_grants`
    MODIFY COLUMN `scopes_json` LONGTEXT NOT NULL;

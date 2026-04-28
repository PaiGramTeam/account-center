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
    'UPDATE `consumer_grants` cg JOIN `bot_account_grants` bg ON bg.`platform_account_ref_id` = cg.`binding_id` SET cg.`scopes_json` = bg.`scopes` WHERE cg.`consumer` = CASE WHEN bg.`bot_id` IN (''bot-paigram'', ''paigram-bot'') THEN ''paigram-bot'' WHEN bg.`bot_id` IN (''bot-pamgram'', ''pamgram'') THEN ''pamgram'' ELSE '''' END AND bg.`deleted_at` IS NULL',
    'SELECT 1'
);

PREPARE backfill_consumer_grant_scopes_stmt FROM @backfill_consumer_grant_scopes_sql;
EXECUTE backfill_consumer_grant_scopes_stmt;
DEALLOCATE PREPARE backfill_consumer_grant_scopes_stmt;

SET @insert_missing_consumer_grants_sql := IF(
    @has_legacy_bot_account_grants,
    'INSERT INTO `consumer_grants` (`binding_id`, `consumer`, `status`, `scopes_json`, `granted_at`, `revoked_at`, `created_at`, `updated_at`) SELECT bg.`platform_account_ref_id`, CASE WHEN bg.`bot_id` IN (''bot-paigram'', ''paigram-bot'') THEN ''paigram-bot'' WHEN bg.`bot_id` IN (''bot-pamgram'', ''pamgram'') THEN ''pamgram'' ELSE '''' END, CASE WHEN bg.`revoked_at` IS NULL THEN ''active'' ELSE ''revoked'' END, bg.`scopes`, bg.`granted_at`, bg.`revoked_at`, bg.`created_at`, bg.`updated_at` FROM `bot_account_grants` bg LEFT JOIN `consumer_grants` cg ON cg.`binding_id` = bg.`platform_account_ref_id` AND cg.`consumer` = CASE WHEN bg.`bot_id` IN (''bot-paigram'', ''paigram-bot'') THEN ''paigram-bot'' WHEN bg.`bot_id` IN (''bot-pamgram'', ''pamgram'') THEN ''pamgram'' ELSE '''' END WHERE bg.`deleted_at` IS NULL AND CASE WHEN bg.`bot_id` IN (''bot-paigram'', ''paigram-bot'') THEN ''paigram-bot'' WHEN bg.`bot_id` IN (''bot-pamgram'', ''pamgram'') THEN ''pamgram'' ELSE '''' END <> '''' AND cg.`id` IS NULL',
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

ALTER TABLE `consumer_grants`
    ADD COLUMN `scopes_json` LONGTEXT NULL AFTER `status`;

UPDATE `consumer_grants` cg
JOIN `bot_account_grants` bg ON bg.`platform_account_ref_id` = cg.`binding_id`
SET cg.`scopes_json` = bg.`scopes`
WHERE cg.`consumer` = CASE
    WHEN bg.`bot_id` IN ('bot-paigram', 'paigram-bot') THEN 'paigram-bot'
    WHEN bg.`bot_id` IN ('bot-pamgram', 'pamgram') THEN 'pamgram'
    ELSE ''
END
AND bg.`deleted_at` IS NULL;

INSERT INTO `consumer_grants` (`binding_id`, `consumer`, `status`, `scopes_json`, `granted_at`, `revoked_at`, `created_at`, `updated_at`)
SELECT
    bg.`platform_account_ref_id`,
    CASE
        WHEN bg.`bot_id` IN ('bot-paigram', 'paigram-bot') THEN 'paigram-bot'
        WHEN bg.`bot_id` IN ('bot-pamgram', 'pamgram') THEN 'pamgram'
        ELSE ''
    END,
    CASE
        WHEN bg.`revoked_at` IS NULL THEN 'active'
        ELSE 'revoked'
    END,
    bg.`scopes`,
    bg.`granted_at`,
    bg.`revoked_at`,
    bg.`created_at`,
    bg.`updated_at`
FROM `bot_account_grants` bg
LEFT JOIN `consumer_grants` cg ON cg.`binding_id` = bg.`platform_account_ref_id`
    AND cg.`consumer` = CASE
        WHEN bg.`bot_id` IN ('bot-paigram', 'paigram-bot') THEN 'paigram-bot'
        WHEN bg.`bot_id` IN ('bot-pamgram', 'pamgram') THEN 'pamgram'
        ELSE ''
    END
WHERE bg.`deleted_at` IS NULL
  AND CASE
        WHEN bg.`bot_id` IN ('bot-paigram', 'paigram-bot') THEN 'paigram-bot'
        WHEN bg.`bot_id` IN ('bot-pamgram', 'pamgram') THEN 'pamgram'
        ELSE ''
      END <> ''
  AND cg.`id` IS NULL;

UPDATE `consumer_grants`
SET `scopes_json` = '[]'
WHERE `scopes_json` IS NULL;

ALTER TABLE `consumer_grants`
    MODIFY COLUMN `scopes_json` LONGTEXT NOT NULL;

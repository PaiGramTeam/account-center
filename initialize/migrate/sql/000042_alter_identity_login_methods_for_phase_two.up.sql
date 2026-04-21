SET @duplicate_provider_account_count := (
    SELECT COUNT(*)
    FROM (
        SELECT provider, provider_account_id
        FROM user_credentials
        GROUP BY provider, provider_account_id
        HAVING COUNT(*) > 1
    ) AS duplicate_provider_accounts
);

SET @duplicate_provider_account_check := IF(
    @duplicate_provider_account_count > 0,
    "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'migration 000042 failed: duplicate provider/provider_account_id rows exist'",
    'DO 0'
);
PREPARE migration_stmt FROM @duplicate_provider_account_check;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;

SET @duplicate_user_provider_count := (
    SELECT COUNT(*)
    FROM (
        SELECT user_id, provider
        FROM user_credentials
        GROUP BY user_id, provider
        HAVING COUNT(*) > 1
    ) AS duplicate_user_providers
);

SET @duplicate_user_provider_check := IF(
    @duplicate_user_provider_count > 0,
    "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'migration 000042 failed: duplicate user/provider rows exist'",
    'DO 0'
);
PREPARE migration_stmt FROM @duplicate_user_provider_check;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;

SET @unresolved_legacy_oauth_count := (
    SELECT COUNT(*)
    FROM users u
    WHERE u.primary_login_type = 'oauth'
      AND NOT EXISTS (
          SELECT 1
          FROM user_credentials uc
          WHERE uc.user_id = u.id
            AND uc.provider <> 'email'
      )
);

SET @unresolved_legacy_oauth_check := IF(
    @unresolved_legacy_oauth_count > 0,
    "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'migration 000042 failed: unresolved oauth users exist'",
    'DO 0'
);
PREPARE migration_stmt FROM @unresolved_legacy_oauth_check;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;

UPDATE users AS u
JOIN (
    SELECT uc.user_id, uc.provider
    FROM user_credentials uc
    WHERE uc.provider <> 'email'
      AND NOT EXISTS (
          SELECT 1
          FROM user_credentials older
          WHERE older.user_id = uc.user_id
            AND older.provider <> 'email'
            AND (
                older.created_at < uc.created_at
                OR (older.created_at = uc.created_at AND older.id < uc.id)
            )
      )
) AS primary_providers
    ON primary_providers.user_id = u.id
SET u.primary_login_type = primary_providers.provider
WHERE u.primary_login_type = 'oauth';

SET @remaining_legacy_oauth_count := (
    SELECT COUNT(*)
    FROM users
    WHERE primary_login_type = 'oauth'
);

SET @remaining_legacy_oauth_check := IF(
    @remaining_legacy_oauth_count > 0,
    "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'migration 000042 failed: oauth users remain after provider migration'",
    'DO 0'
);
PREPARE migration_stmt FROM @remaining_legacy_oauth_check;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;

ALTER TABLE user_credentials
    DROP INDEX uniq_user_provider,
    DROP INDEX idx_provider_account,
    ADD UNIQUE KEY uniq_provider_account (provider, provider_account_id),
    ADD UNIQUE KEY uniq_user_provider (user_id, provider);

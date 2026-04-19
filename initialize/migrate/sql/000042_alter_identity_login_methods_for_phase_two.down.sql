UPDATE users
SET primary_login_type = 'oauth'
WHERE primary_login_type IN ('google', 'github', 'telegram');

ALTER TABLE user_credentials
    DROP INDEX uniq_user_provider,
    DROP INDEX uniq_provider_account,
    ADD UNIQUE KEY uniq_user_provider (user_id, provider, provider_account_id),
    ADD KEY idx_provider_account (provider, provider_account_id);

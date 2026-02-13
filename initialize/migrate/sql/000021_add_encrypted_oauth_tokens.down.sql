-- Rollback: Remove encrypted OAuth token columns

ALTER TABLE user_credentials
    DROP COLUMN access_token_encrypted,
    DROP COLUMN refresh_token_encrypted;

DROP INDEX idx_user_credentials_provider_user ON user_credentials;
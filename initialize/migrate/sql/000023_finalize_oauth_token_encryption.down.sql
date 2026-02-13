-- Rollback: Restore plaintext token columns
-- WARNING: This will lose data! Encrypted tokens cannot be restored to plaintext.

-- Rename encrypted columns back
ALTER TABLE user_credentials
    CHANGE COLUMN access_token access_token_encrypted TEXT NULL COMMENT 'AES-256-GCM encrypted OAuth access token',
    CHANGE COLUMN refresh_token refresh_token_encrypted TEXT NULL COMMENT 'AES-256-GCM encrypted OAuth refresh token';

-- Re-add plaintext columns (will be empty)
ALTER TABLE user_credentials
    ADD COLUMN access_token VARCHAR(1024) NULL AFTER provider_account_id,
    ADD COLUMN refresh_token VARCHAR(1024) NULL AFTER access_token;
-- Remove plaintext OAuth token columns after migration to encrypted format
-- IMPORTANT: Only run this after verifying all tokens are successfully encrypted!

-- Remove plaintext token columns
ALTER TABLE user_credentials
    DROP COLUMN access_token,
    DROP COLUMN refresh_token;

-- Rename encrypted columns to be the primary columns
ALTER TABLE user_credentials
    CHANGE COLUMN access_token_encrypted access_token TEXT NULL COMMENT 'AES-256-GCM encrypted OAuth access token',
    CHANGE COLUMN refresh_token_encrypted refresh_token TEXT NULL COMMENT 'AES-256-GCM encrypted OAuth refresh token';
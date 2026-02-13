-- Add encrypted OAuth token columns to user_credentials
-- This migration adds new encrypted columns while preserving existing plaintext columns
-- The plaintext columns will be removed in migration 000022 after data migration

ALTER TABLE user_credentials
    ADD COLUMN access_token_encrypted TEXT NULL COMMENT 'AES-256-GCM encrypted OAuth access token' AFTER access_token,
    ADD COLUMN refresh_token_encrypted TEXT NULL COMMENT 'AES-256-GCM encrypted OAuth refresh token' AFTER refresh_token;

-- Add index for faster lookups by provider
CREATE INDEX idx_user_credentials_provider_user ON user_credentials(provider, user_id);
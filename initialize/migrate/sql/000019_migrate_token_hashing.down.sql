-- Rollback migration: Remove the hash columns

ALTER TABLE user_sessions
DROP INDEX idx_access_token_hash,
DROP INDEX idx_refresh_token_hash,
DROP COLUMN access_token_hash,
DROP COLUMN refresh_token_hash;
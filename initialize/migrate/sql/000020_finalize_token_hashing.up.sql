-- Complete the token hashing migration
-- This migration should be run AFTER all existing sessions have been invalidated
-- or migrated to use hashed tokens

-- Step 1: Drop old indexes
ALTER TABLE user_sessions
DROP INDEX uniq_access_token,
DROP INDEX uniq_refresh_token;

-- Step 2: Drop old token columns
ALTER TABLE user_sessions
DROP COLUMN access_token,
DROP COLUMN refresh_token;

-- Step 3: Make hash columns NOT NULL and UNIQUE
ALTER TABLE user_sessions
DROP INDEX idx_access_token_hash,
DROP INDEX idx_refresh_token_hash,
MODIFY COLUMN access_token_hash VARCHAR(64) NOT NULL,
MODIFY COLUMN refresh_token_hash VARCHAR(64) NOT NULL,
ADD UNIQUE KEY uniq_access_token_hash (access_token_hash),
ADD UNIQUE KEY uniq_refresh_token_hash (refresh_token_hash);
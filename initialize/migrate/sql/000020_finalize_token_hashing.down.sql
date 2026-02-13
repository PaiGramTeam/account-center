-- Rollback: Restore original token columns
-- WARNING: This will lose all session data!

-- Step 1: Drop hash constraints and indexes
ALTER TABLE user_sessions
DROP INDEX uniq_access_token_hash,
DROP INDEX uniq_refresh_token_hash,
MODIFY COLUMN access_token_hash VARCHAR(64) NULL,
MODIFY COLUMN refresh_token_hash VARCHAR(64) NULL;

-- Step 2: Re-add original columns
ALTER TABLE user_sessions
ADD COLUMN access_token VARCHAR(255) NULL AFTER user_id,
ADD COLUMN refresh_token VARCHAR(255) NULL AFTER access_token;

-- Step 3: Re-add original indexes
ALTER TABLE user_sessions
ADD UNIQUE KEY uniq_access_token (access_token),
ADD UNIQUE KEY uniq_refresh_token (refresh_token),
ADD INDEX idx_access_token_hash (access_token_hash),
ADD INDEX idx_refresh_token_hash (refresh_token_hash);
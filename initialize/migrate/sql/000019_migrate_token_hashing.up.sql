-- Migration to convert plain-text tokens to SHA-256 hashes for better security
-- This migration adds new hash columns and will be followed by a data migration

-- Step 1: Add new columns for token hashes
ALTER TABLE user_sessions
ADD COLUMN access_token_hash VARCHAR(64) NULL AFTER user_id,
ADD COLUMN refresh_token_hash VARCHAR(64) NULL AFTER access_token_hash;

-- Step 2: Create indexes on the new hash columns (will be unique after data migration)
-- For now, just add regular indexes to allow null values during migration
ALTER TABLE user_sessions
ADD INDEX idx_access_token_hash (access_token_hash),
ADD INDEX idx_refresh_token_hash (refresh_token_hash);

-- Step 3: The old columns will be removed in a later migration after data is migrated
-- For now, both old and new columns exist to allow gradual migration
-- Make hash fields NOT NULL and remove old plaintext fields
ALTER TABLE bot_tokens
    MODIFY COLUMN access_token_hash VARCHAR(64) NOT NULL,
    MODIFY COLUMN refresh_token_hash VARCHAR(64) NOT NULL;

-- Remove old plaintext token columns (no longer needed)
ALTER TABLE bot_tokens
    DROP COLUMN access_token,
    DROP COLUMN refresh_token;

-- Remove old indexes that are no longer needed
ALTER TABLE bot_tokens
    DROP INDEX uniq_access_token,
    DROP INDEX uniq_refresh_token;

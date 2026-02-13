-- Restore plaintext token columns
ALTER TABLE bot_tokens
    ADD COLUMN access_token VARCHAR(512) NULL AFTER bot_id,
    ADD COLUMN refresh_token VARCHAR(512) NULL AFTER access_token;

-- Restore old indexes
CREATE UNIQUE INDEX uniq_access_token ON bot_tokens(access_token);
CREATE UNIQUE INDEX uniq_refresh_token ON bot_tokens(refresh_token);

-- Make hash fields nullable again
ALTER TABLE bot_tokens
    MODIFY COLUMN access_token_hash VARCHAR(64) NULL,
    MODIFY COLUMN refresh_token_hash VARCHAR(64) NULL;
-- Add hash fields for bot tokens (security)
ALTER TABLE bot_tokens
    ADD COLUMN access_token_hash VARCHAR(64) NULL AFTER bot_id,
    ADD COLUMN refresh_token_hash VARCHAR(64) NULL AFTER access_token_hash;

-- Add rate limiting fields
ALTER TABLE bot_tokens
    ADD COLUMN rate_limit_enabled BOOLEAN NOT NULL DEFAULT TRUE AFTER refresh_token_hash,
    ADD COLUMN rate_limit_time_window BIGINT NULL COMMENT 'Time window in milliseconds' AFTER rate_limit_enabled,
    ADD COLUMN rate_limit_max INT NULL COMMENT 'Max requests within time window' AFTER rate_limit_time_window,
    ADD COLUMN request_count INT NOT NULL DEFAULT 0 AFTER rate_limit_max,
    ADD COLUMN last_request DATETIME(3) NULL AFTER request_count;

-- Create unique indexes on hash fields
CREATE UNIQUE INDEX uniq_access_token_hash ON bot_tokens(access_token_hash);
CREATE UNIQUE INDEX uniq_refresh_token_hash ON bot_tokens(refresh_token_hash);

-- Create index for rate limiting queries
CREATE INDEX idx_last_request ON bot_tokens(last_request);
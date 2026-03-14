-- Remove indexes
ALTER TABLE bot_tokens
    DROP INDEX idx_last_request,
    DROP INDEX uniq_refresh_token_hash,
    DROP INDEX uniq_access_token_hash;

-- Remove rate limiting fields
ALTER TABLE bot_tokens
    DROP COLUMN last_request,
    DROP COLUMN request_count,
    DROP COLUMN rate_limit_max,
    DROP COLUMN rate_limit_time_window,
    DROP COLUMN rate_limit_enabled;

-- Remove hash fields
ALTER TABLE bot_tokens
    DROP COLUMN refresh_token_hash,
    DROP COLUMN access_token_hash;

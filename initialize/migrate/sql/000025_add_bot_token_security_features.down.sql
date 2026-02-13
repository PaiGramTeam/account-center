-- Remove indexes
DROP INDEX IF EXISTS idx_last_request ON bot_tokens;
DROP INDEX IF EXISTS uniq_refresh_token_hash ON bot_tokens;
DROP INDEX IF EXISTS uniq_access_token_hash ON bot_tokens;

-- Remove rate limiting fields
ALTER TABLE bot_tokens
    DROP COLUMN IF EXISTS last_request,
    DROP COLUMN IF EXISTS request_count,
    DROP COLUMN IF EXISTS rate_limit_max,
    DROP COLUMN IF EXISTS rate_limit_time_window,
    DROP COLUMN IF EXISTS rate_limit_enabled;

-- Remove hash fields
ALTER TABLE bot_tokens
    DROP COLUMN IF EXISTS refresh_token_hash,
    DROP COLUMN IF EXISTS access_token_hash;
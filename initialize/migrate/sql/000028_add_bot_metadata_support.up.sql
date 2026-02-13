-- Add metadata support for bots and bot tokens
ALTER TABLE bots
    ADD COLUMN metadata JSON NULL COMMENT 'Custom metadata (e.g., subscription plan, client version)' AFTER scopes;

ALTER TABLE bot_tokens
    ADD COLUMN metadata JSON NULL COMMENT 'Custom metadata for this token' AFTER last_request;
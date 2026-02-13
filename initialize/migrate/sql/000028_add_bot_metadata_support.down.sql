-- Remove metadata fields
ALTER TABLE bot_tokens
    DROP COLUMN IF EXISTS metadata;

ALTER TABLE bots
    DROP COLUMN IF EXISTS metadata;
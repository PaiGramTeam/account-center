-- Reverse the token-family rotation columns added in 000002.
DROP INDEX idx_bot_tokens_status ON bot_tokens;
DROP INDEX idx_bot_tokens_family_id ON bot_tokens;

ALTER TABLE bot_tokens
    DROP COLUMN revoked_reason,
    DROP COLUMN status,
    DROP COLUMN family_id;

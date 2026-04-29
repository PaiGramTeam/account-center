-- Token-family rotation columns for bot_tokens.
-- Rationale: detect refresh-token reuse by tying every rotated row to a stable
-- family_id and tracking each row's lifecycle status. When reuse is detected
-- on any row in a family, the whole family is revoked. See V11 hardening.

ALTER TABLE bot_tokens
    ADD COLUMN family_id CHAR(36) NOT NULL DEFAULT '' AFTER bot_id,
    ADD COLUMN status VARCHAR(32) NOT NULL DEFAULT 'active' AFTER revoked_at,
    ADD COLUMN revoked_reason VARCHAR(64) NOT NULL DEFAULT '' AFTER status;

-- Backfill family_id for any pre-existing rows so we maintain the NOT NULL
-- invariant. Each row becomes its own one-row family. The default-empty rows
-- stay safe because they will fail to match any new family-keyed lookup.
UPDATE bot_tokens
SET family_id = UUID()
WHERE family_id = '';

CREATE INDEX idx_bot_tokens_family_id ON bot_tokens (family_id);
CREATE INDEX idx_bot_tokens_status ON bot_tokens (status);

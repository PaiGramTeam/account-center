-- This migration handles the transition from plaintext to hashed tokens
-- Since we cannot reverse-hash existing tokens, we'll need to:
-- 1. Mark all existing tokens as needing re-authentication
-- 2. In production, bot owners will need to re-login to get new tokens

-- For existing tokens, we cannot compute hashes from plaintext
-- So we'll mark them as revoked to force re-authentication
UPDATE bot_tokens
SET revoked_at = NOW()
WHERE access_token_hash IS NULL 
  AND revoked_at IS NULL;

-- Add a note: In development, you may want to truncate the table instead
-- TRUNCATE TABLE bot_tokens;
-- Migrate existing OAuth tokens from plaintext to encrypted format
-- This migration encrypts existing access_token and refresh_token values
-- Note: This must be run with the application's ENCRYPTION_KEY environment variable set

-- The actual data migration will be handled by the application code
-- This migration just marks the transition point

-- Application migration code should:
-- 1. Load ENCRYPTION_KEY from environment
-- 2. For each user_credential with non-null access_token or refresh_token:
--    a. Encrypt access_token -> access_token_encrypted
--    b. Encrypt refresh_token -> refresh_token_encrypted
--    c. Verify decryption works
--    d. Set access_token and refresh_token to NULL (to be removed in next migration)

-- No SQL changes needed here - the migration is code-based
-- This file exists to maintain migration sequence numbering
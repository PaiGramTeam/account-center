-- Rollback: Decrypt tokens back to plaintext
-- Note: This rollback requires ENCRYPTION_KEY to be set

-- Application rollback code should:
-- 1. For each user_credential with non-null encrypted tokens:
--    a. Decrypt access_token_encrypted -> access_token
--    b. Decrypt refresh_token_encrypted -> refresh_token
--    c. Clear encrypted columns

-- No SQL changes needed - rollback is code-based
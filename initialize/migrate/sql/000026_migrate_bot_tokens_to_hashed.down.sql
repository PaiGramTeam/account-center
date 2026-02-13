-- Cannot reverse this migration as we cannot unhash tokens
-- This migration is irreversible
SELECT 'Cannot reverse migration: hashed tokens cannot be converted back to plaintext' AS warning;
-- Add PKCE support to OAuth state table
-- code_verifier is used for Proof Key for Code Exchange (RFC 7636)
-- This prevents authorization code interception attacks

ALTER TABLE user_oauth_states
    ADD COLUMN code_verifier VARCHAR(255) NULL COMMENT 'PKCE code verifier for secure authorization code exchange';

CREATE INDEX idx_oauth_state_code_verifier ON user_oauth_states(code_verifier);
-- Rollback PKCE support

DROP INDEX idx_oauth_state_code_verifier ON user_oauth_states;

ALTER TABLE user_oauth_states
    DROP COLUMN code_verifier;
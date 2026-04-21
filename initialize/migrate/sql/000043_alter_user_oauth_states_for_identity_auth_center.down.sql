ALTER TABLE user_oauth_states
    DROP FOREIGN KEY fk_user_oauth_states_user,
    DROP INDEX idx_user_oauth_states_user_id,
    DROP INDEX idx_user_oauth_states_purpose,
    DROP COLUMN user_id,
    DROP COLUMN purpose;

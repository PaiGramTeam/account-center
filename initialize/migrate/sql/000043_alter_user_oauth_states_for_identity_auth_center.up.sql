ALTER TABLE user_oauth_states
    ADD COLUMN purpose VARCHAR(64) NOT NULL DEFAULT 'login' AFTER state,
    ADD COLUMN user_id BIGINT UNSIGNED NULL AFTER purpose,
    ADD KEY idx_user_oauth_states_purpose (purpose),
    ADD KEY idx_user_oauth_states_user_id (user_id),
    ADD CONSTRAINT fk_user_oauth_states_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE;

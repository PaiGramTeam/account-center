-- Reverse the OAuth-state client-binding columns added in 000003.
ALTER TABLE user_oauth_states
    DROP COLUMN user_agent,
    DROP COLUMN client_ip;

-- Bind OAuth state to the originating client's IP and User-Agent.
-- Rationale: without these checks an attacker who phishes a victim's state
-- token can replay it from a different machine to consume the OAuth code.
-- See V23 hardening.
--
-- IMPORTANT: full-IP equality is strict. Mobile networks (NAT/CGNAT) can
-- legitimately switch the egress IP between OAuth start and OAuth callback.
-- We accept that trade-off for now and revisit (e.g. /24-prefix matching)
-- if it produces meaningful false positives in production telemetry.

ALTER TABLE user_oauth_states
    ADD COLUMN client_ip VARCHAR(64) NOT NULL DEFAULT '' AFTER code_verifier,
    ADD COLUMN user_agent VARCHAR(255) NOT NULL DEFAULT '' AFTER client_ip;

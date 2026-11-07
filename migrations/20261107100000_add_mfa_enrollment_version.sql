ALTER TABLE mfa_totp_credentials
    ADD COLUMN IF NOT EXISTS enrollment_version BIGINT NOT NULL DEFAULT 0;

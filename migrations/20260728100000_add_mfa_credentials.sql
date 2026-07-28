CREATE TABLE IF NOT EXISTS mfa_totp_credentials (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    encrypted_seed TEXT NOT NULL,
    enabled_at TIMESTAMP,
    last_verified_step BIGINT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, code_hash)
);

CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_available
    ON mfa_recovery_codes (user_id)
    WHERE used_at IS NULL;

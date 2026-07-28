CREATE TABLE IF NOT EXISTS mfa_recent_verifications (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_jti TEXT NOT NULL,
    verified_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    PRIMARY KEY (user_id, token_jti)
);

CREATE INDEX IF NOT EXISTS idx_mfa_recent_verifications_expires_at
    ON mfa_recent_verifications (expires_at);

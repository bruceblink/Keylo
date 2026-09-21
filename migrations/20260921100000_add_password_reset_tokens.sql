-- Store only short-lived password-recovery proofs; the plaintext token exists
-- only in the delivery request and is never recoverable from the database.
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email_snapshot TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    consumed_at TIMESTAMP,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_pending
    ON password_reset_tokens (user_id, expires_at)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

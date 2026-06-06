CREATE TABLE IF NOT EXISTS refresh_sessions (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    current_refresh_token_id TEXT NOT NULL,
    current_access_jti TEXT NOT NULL,
    issued_at TIMESTAMP NOT NULL DEFAULT NOW(),
    rotated_at TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    revoke_reason TEXT,
    FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_refresh_sessions_principal_id
    ON refresh_sessions (principal_id);
CREATE INDEX IF NOT EXISTS idx_refresh_sessions_client_id
    ON refresh_sessions (client_id);
CREATE INDEX IF NOT EXISTS idx_refresh_sessions_active
    ON refresh_sessions (principal_id, client_id)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_refresh_sessions_expires_at
    ON refresh_sessions (expires_at);

CREATE TABLE IF NOT EXISTS refresh_session_tokens (
    token_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    issued_at TIMESTAMP NOT NULL DEFAULT NOW(),
    consumed_at TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES refresh_sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_refresh_session_tokens_session_id
    ON refresh_session_tokens (session_id);
CREATE INDEX IF NOT EXISTS idx_refresh_session_tokens_hash
    ON refresh_session_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_session_tokens_expires_at
    ON refresh_session_tokens (expires_at);

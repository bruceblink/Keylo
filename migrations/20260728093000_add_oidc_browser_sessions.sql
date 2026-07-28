CREATE TABLE IF NOT EXISTS oidc_browser_sessions (
    id TEXT PRIMARY KEY,
    session_hash TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oidc_browser_sessions_user_id
    ON oidc_browser_sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_oidc_browser_sessions_expires_at
    ON oidc_browser_sessions (expires_at);

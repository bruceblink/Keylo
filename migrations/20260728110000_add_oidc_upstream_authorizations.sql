CREATE TABLE IF NOT EXISTS oidc_upstream_authorizations (
    id TEXT PRIMARY KEY,
    state_hash TEXT NOT NULL UNIQUE,
    source_id TEXT NOT NULL REFERENCES identity_sources(id) ON DELETE CASCADE,
    nonce_hash TEXT NOT NULL,
    code_verifier_hash TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    consumed_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oidc_upstream_authorizations_active
    ON oidc_upstream_authorizations (source_id, expires_at)
    WHERE consumed_at IS NULL;

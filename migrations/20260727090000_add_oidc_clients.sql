CREATE TABLE IF NOT EXISTS oidc_clients (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL UNIQUE,
    client_secret_hash TEXT,
    name TEXT NOT NULL,
    description TEXT,
    client_type TEXT NOT NULL CHECK (client_type IN ('public', 'confidential')),
    redirect_uris TEXT[] NOT NULL,
    grant_types TEXT[] NOT NULL DEFAULT ARRAY['authorization_code']::TEXT[],
    scopes TEXT[] NOT NULL DEFAULT ARRAY['openid', 'profile', 'email']::TEXT[],
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oidc_clients_active ON oidc_clients (active);

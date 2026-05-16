CREATE TABLE IF NOT EXISTS identity_sources (
    id                 TEXT PRIMARY KEY,
    name               TEXT UNIQUE NOT NULL,
    source_type        TEXT NOT NULL CHECK (source_type IN ('local_password', 'oauth2', 'oidc_upstream', 'ldap')),
    display_name       TEXT NOT NULL,
    description        TEXT,
    config             JSONB NOT NULL DEFAULT '{}'::jsonb,
    claim_mapping      JSONB NOT NULL DEFAULT '{}'::jsonb,
    jit_enabled        BOOLEAN NOT NULL DEFAULT FALSE,
    auto_link_enabled  BOOLEAN NOT NULL DEFAULT TRUE,
    active             BOOLEAN NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_identity_sources_active_name
    ON identity_sources (name)
    WHERE active = TRUE;

CREATE INDEX IF NOT EXISTS idx_identity_sources_source_type
    ON identity_sources (source_type);

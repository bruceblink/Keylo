-- Service clients table for service-to-service (S2S) authentication
CREATE TABLE IF NOT EXISTS service_clients (
    service_id        TEXT PRIMARY KEY,
    secret_hash       TEXT NOT NULL,
    name              TEXT NOT NULL,
    description       TEXT,
    allowed_scopes    TEXT[] NOT NULL DEFAULT '{}',
    allowed_audiences TEXT[] NOT NULL DEFAULT '{}',
    active            BOOLEAN NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_service_clients_active ON service_clients (active);

ALTER TABLE service_clients
    ADD COLUMN IF NOT EXISTS integration_type TEXT NOT NULL DEFAULT 'internal',
    ADD COLUMN IF NOT EXISTS introspection_allowed BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS token_ttl_seconds BIGINT,
    ADD COLUMN IF NOT EXISTS owner TEXT,
    ADD COLUMN IF NOT EXISTS contact TEXT;

CREATE INDEX IF NOT EXISTS idx_service_clients_integration_type
    ON service_clients (integration_type);

CREATE INDEX IF NOT EXISTS idx_service_clients_introspection_allowed
    ON service_clients (introspection_allowed)
    WHERE active = TRUE;

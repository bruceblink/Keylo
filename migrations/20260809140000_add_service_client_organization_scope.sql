-- Service clients are either explicit platform identities or owned by one
-- organization. Existing clients predate tenant ownership and remain platform
-- scoped rather than being silently assigned to a customer organization.
ALTER TABLE service_clients
    ADD COLUMN IF NOT EXISTS organization_id TEXT;

ALTER TABLE service_clients
    ADD COLUMN IF NOT EXISTS scope_kind TEXT;

UPDATE service_clients
SET scope_kind = CASE
    WHEN organization_id IS NULL THEN 'platform'
    ELSE 'organization'
END
WHERE scope_kind IS NULL;

ALTER TABLE service_clients
    ALTER COLUMN scope_kind SET DEFAULT 'platform',
    ALTER COLUMN scope_kind SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'service_clients_organization_id_fkey'
          AND conrelid = 'service_clients'::regclass
    ) THEN
        ALTER TABLE service_clients
            ADD CONSTRAINT service_clients_organization_id_fkey
            FOREIGN KEY (organization_id)
            REFERENCES organizations(id)
            ON DELETE RESTRICT;
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'service_clients_scope_kind_check'
          AND conrelid = 'service_clients'::regclass
    ) THEN
        ALTER TABLE service_clients
            ADD CONSTRAINT service_clients_scope_kind_check
            CHECK (
                (scope_kind = 'platform' AND organization_id IS NULL)
                OR (scope_kind = 'organization' AND organization_id IS NOT NULL)
            );
    END IF;
END
$$;

-- Tenant service listings use this index, while the service_id primary key
-- remains the lookup path for client-credentials authentication.
CREATE INDEX IF NOT EXISTS idx_service_clients_organization_active
    ON service_clients (organization_id, active, created_at DESC)
    WHERE organization_id IS NOT NULL;

-- Moving a machine identity between platform and tenant scope changes its
-- authorization boundary. Require an explicit replacement instead of letting
-- a regular update accidentally repurpose an existing credential.
CREATE OR REPLACE FUNCTION enforce_service_client_scope_immutability()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.scope_kind IS DISTINCT FROM OLD.scope_kind
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id THEN
        RAISE EXCEPTION 'service client scope is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'service_clients_scope_immutable';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_service_clients_scope_immutable ON service_clients;

CREATE TRIGGER trg_service_clients_scope_immutable
BEFORE UPDATE OF scope_kind, organization_id ON service_clients
FOR EACH ROW
EXECUTE FUNCTION enforce_service_client_scope_immutability();

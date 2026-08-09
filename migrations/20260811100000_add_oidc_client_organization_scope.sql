-- Relying parties are either platform-wide or owned by exactly one organization.
-- Existing registrations predate tenant ownership and remain explicit platform clients.
ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS scope_kind TEXT,
    ADD COLUMN IF NOT EXISTS organization_id TEXT;

UPDATE oidc_clients
SET scope_kind = CASE
    WHEN organization_id IS NULL THEN 'platform'
    ELSE 'organization'
END
WHERE scope_kind IS NULL;

ALTER TABLE oidc_clients
    ALTER COLUMN scope_kind SET DEFAULT 'platform',
    ALTER COLUMN scope_kind SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'oidc_clients_organization_id_fkey'
    ) THEN
        ALTER TABLE oidc_clients
            ADD CONSTRAINT oidc_clients_organization_id_fkey
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE RESTRICT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'oidc_clients_scope_check'
    ) THEN
        ALTER TABLE oidc_clients
            ADD CONSTRAINT oidc_clients_scope_check CHECK (
                (scope_kind = 'platform' AND organization_id IS NULL)
                OR (scope_kind = 'organization' AND organization_id IS NOT NULL)
            );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_oidc_clients_organization
    ON oidc_clients (organization_id, active, created_at DESC)
    WHERE organization_id IS NOT NULL;

CREATE OR REPLACE FUNCTION prevent_oidc_client_scope_change()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.scope_kind IS DISTINCT FROM OLD.scope_kind
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id THEN
        RAISE EXCEPTION 'oidc_client_scope_is_immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_oidc_client_scope_immutable ON oidc_clients;
CREATE TRIGGER trg_oidc_client_scope_immutable
BEFORE UPDATE OF scope_kind, organization_id ON oidc_clients
FOR EACH ROW EXECUTE FUNCTION prevent_oidc_client_scope_change();

ALTER TABLE oidc_authorization_codes
    ADD COLUMN IF NOT EXISTS organization_id TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'oidc_authorization_codes_organization_id_fkey'
    ) THEN
        ALTER TABLE oidc_authorization_codes
            ADD CONSTRAINT oidc_authorization_codes_organization_id_fkey
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE RESTRICT;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_oidc_authorization_codes_organization
    ON oidc_authorization_codes (organization_id, expires_at)
    WHERE organization_id IS NOT NULL AND consumed_at IS NULL;

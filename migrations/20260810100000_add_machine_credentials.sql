-- Devices are independent machine Principals with one immutable platform or
-- organization scope. Unlike a nullable membership alone, this makes a device
-- boundary explicit and prevents a key from being repurposed across tenants.
CREATE TABLE IF NOT EXISTS device_principal_scopes (
    principal_id    TEXT PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
    scope_kind      TEXT NOT NULL,
    organization_id TEXT REFERENCES organizations(id) ON DELETE RESTRICT,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT device_principal_scopes_scope_check CHECK (
        (scope_kind = 'platform' AND organization_id IS NULL)
        OR (scope_kind = 'organization' AND organization_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_device_principal_scopes_organization
    ON device_principal_scopes (organization_id, principal_id)
    WHERE organization_id IS NOT NULL;

-- A device cannot migrate between platform and organization ownership. A
-- replacement device is required so existing credentials never gain a new
-- authorization boundary through an ordinary update.
CREATE OR REPLACE FUNCTION enforce_device_principal_scope_immutability()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.scope_kind IS DISTINCT FROM OLD.scope_kind
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id THEN
        RAISE EXCEPTION 'device principal scope is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'device_principal_scope_immutable';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_device_principal_scope_immutable ON device_principal_scopes;

CREATE TRIGGER trg_device_principal_scope_immutable
BEFORE UPDATE OF scope_kind, organization_id ON device_principal_scopes
FOR EACH ROW
EXECUTE FUNCTION enforce_device_principal_scope_immutability();

-- Raw API keys are never persisted. key_id/prefix select exactly one record,
-- while BCrypt protects the random secret suffix shown only on create/rotate.
CREATE TABLE IF NOT EXISTS machine_credentials (
    key_id                  TEXT PRIMARY KEY,
    prefix                  TEXT NOT NULL UNIQUE,
    secret_hash             TEXT NOT NULL,
    principal_id            TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    organization_id         TEXT REFERENCES organizations(id) ON DELETE RESTRICT,
    status                  TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked')),
    expires_at              TIMESTAMP,
    last_used_at            TIMESTAMP,
    created_by_principal_id TEXT REFERENCES principals(id) ON DELETE SET NULL,
    allowed_scopes          TEXT[] NOT NULL,
    allowed_audiences       TEXT[] NOT NULL,
    revoked_at              TIMESTAMP,
    revoke_reason           TEXT,
    created_at              TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT machine_credentials_scopes_not_empty CHECK (cardinality(allowed_scopes) > 0),
    CONSTRAINT machine_credentials_audiences_not_empty CHECK (cardinality(allowed_audiences) > 0)
);

CREATE INDEX IF NOT EXISTS idx_machine_credentials_principal_scope
    ON machine_credentials (principal_id, organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_machine_credentials_live
    ON machine_credentials (key_id, expires_at)
    WHERE status = 'active';

-- Customer support is deliberately a narrow, audited cross-organization path.
-- It is not represented as organization membership or an organization role binding.

DO $$
DECLARE
    existing_role_id TEXT;
    existing_scope TEXT;
    existing_assignable_to TEXT;
    existing_system BOOLEAN;
BEGIN
    SELECT id, scope, assignable_to, system
    INTO existing_role_id, existing_scope, existing_assignable_to, existing_system
    FROM roles
    WHERE name = 'customer_support'
    FOR UPDATE;

    IF FOUND THEN
        IF existing_scope <> 'platform'
           OR existing_assignable_to <> 'user'
           OR existing_system IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'customer_support role has incompatible configuration';
        END IF;
    ELSE
        -- A stable UUID keeps this system role reproducible without requiring a
        -- database extension solely to generate an identifier during migration.
        INSERT INTO roles (id, name, description, assignable_to, system, scope)
        VALUES (
            '8b1e397a-3e9e-42e8-a49f-aea4720df74f',
            'customer_support',
            'Restricted, audited customer support access role',
            'user',
            TRUE,
            'platform'
        );
        existing_role_id := '8b1e397a-3e9e-42e8-a49f-aea4720df74f';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM role_permissions
        WHERE role_id = existing_role_id
    ) THEN
        RAISE EXCEPTION 'customer_support role must not have permissions';
    END IF;
END
$$;

-- Keep the fixed role from being repurposed through the normal role-management
-- endpoints. Its description may still be clarified without changing authority.
CREATE OR REPLACE FUNCTION enforce_customer_support_role_invariants()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.name = 'customer_support' THEN
            RAISE EXCEPTION 'customer_support role is immutable';
        END IF;
        RETURN OLD;
    END IF;

    IF OLD.name = 'customer_support' OR NEW.name = 'customer_support' THEN
        IF NEW.name <> 'customer_support'
           OR NEW.scope <> 'platform'
           OR NEW.assignable_to <> 'user'
           OR NEW.system IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'customer_support role has incompatible configuration';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_customer_support_role_invariants ON roles;

CREATE TRIGGER trg_customer_support_role_invariants
BEFORE UPDATE OR DELETE ON roles
FOR EACH ROW
EXECUTE FUNCTION enforce_customer_support_role_invariants();

-- Support authority is carried by a grant, never by generic RBAC permissions.
CREATE OR REPLACE FUNCTION prevent_customer_support_role_permissions()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM roles
        WHERE id = NEW.role_id
          AND name = 'customer_support'
    ) THEN
        RAISE EXCEPTION 'customer_support role must not have permissions';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_customer_support_role_permissions ON role_permissions;

CREATE TRIGGER trg_customer_support_role_permissions
BEFORE INSERT OR UPDATE OF role_id ON role_permissions
FOR EACH ROW
EXECUTE FUNCTION prevent_customer_support_role_permissions();

CREATE TABLE IF NOT EXISTS customer_support_access_grants (
    id                       TEXT PRIMARY KEY,
    support_principal_id     TEXT NOT NULL REFERENCES principals(id) ON DELETE RESTRICT,
    organization_id          TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    reason                   TEXT NOT NULL,
    granted_by_principal_id  TEXT NOT NULL,
    granted_at               TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at               TIMESTAMP NOT NULL,
    revoked_at               TIMESTAMP,
    revoked_by_principal_id  TEXT,
    revoke_reason            TEXT,
    CONSTRAINT customer_support_access_grants_reason_check
        CHECK (char_length(btrim(reason)) BETWEEN 1 AND 1000),
    CONSTRAINT customer_support_access_grants_revocation_check
        CHECK (
            (revoked_at IS NULL
             AND revoked_by_principal_id IS NULL
             AND revoke_reason IS NULL)
            OR
            (revoked_at IS NOT NULL
             AND revoked_by_principal_id IS NOT NULL
             AND char_length(btrim(revoke_reason)) BETWEEN 1 AND 1000)
        )
);

CREATE INDEX IF NOT EXISTS idx_customer_support_access_grants_support_principal
    ON customer_support_access_grants (support_principal_id, revoked_at, expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_customer_support_access_grants_organization
    ON customer_support_access_grants (organization_id, revoked_at, expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_customer_support_access_grants_granted_by
    ON customer_support_access_grants (granted_by_principal_id, granted_at DESC);

CREATE TABLE IF NOT EXISTS customer_support_access_grant_operations (
    grant_id  TEXT NOT NULL REFERENCES customer_support_access_grants(id) ON DELETE CASCADE,
    operation TEXT NOT NULL,
    PRIMARY KEY (grant_id, operation),
    CONSTRAINT customer_support_access_grant_operations_operation_check
        CHECK (operation IN (
            'organization.read',
            'membership.read',
            'authorization_audit.read',
            'refresh_session.read',
            'resource.read'
        ))
);

CREATE INDEX IF NOT EXISTS idx_customer_support_access_grant_operations_operation
    ON customer_support_access_grant_operations (operation, grant_id);

-- Audit identifiers intentionally have no foreign keys. A denied attempt can
-- mention an expired, revoked, deleted, or never-valid identifier and must still
-- be recorded for investigation.
CREATE TABLE IF NOT EXISTS customer_support_audit_logs (
    id                  TEXT PRIMARY KEY,
    grant_id            TEXT,
    actor_principal_id  TEXT,
    organization_id     TEXT NOT NULL,
    operation           TEXT NOT NULL,
    reason_snapshot     TEXT NOT NULL,
    target_type         TEXT NOT NULL,
    target_id           TEXT,
    outcome             TEXT NOT NULL,
    denial_reason       TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT customer_support_audit_logs_operation_check
        CHECK (operation IN (
            'organization.read',
            'membership.read',
            'authorization_audit.read',
            'refresh_session.read',
            'resource.read',
            'grant.created',
            'grant.revoked',
            'context.issued'
        )),
    CONSTRAINT customer_support_audit_logs_reason_snapshot_check
        CHECK (char_length(btrim(reason_snapshot)) BETWEEN 1 AND 1000),
    CONSTRAINT customer_support_audit_logs_target_type_check
        CHECK (target_type IN (
            'organization',
            'membership',
            'authorization_audit_log',
            'refresh_session',
            'resource',
            'customer_support_access_grant'
        )),
    CONSTRAINT customer_support_audit_logs_outcome_check
        CHECK (outcome IN ('allow', 'deny')),
    CONSTRAINT customer_support_audit_logs_denial_reason_check
        CHECK (
            (outcome = 'allow' AND denial_reason IS NULL)
            OR
            (outcome = 'deny' AND char_length(btrim(denial_reason)) BETWEEN 1 AND 200)
        )
);

CREATE INDEX IF NOT EXISTS idx_customer_support_audit_logs_organization_created
    ON customer_support_audit_logs (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_customer_support_audit_logs_actor_created
    ON customer_support_audit_logs (actor_principal_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_customer_support_audit_logs_grant_created
    ON customer_support_audit_logs (grant_id, created_at DESC);

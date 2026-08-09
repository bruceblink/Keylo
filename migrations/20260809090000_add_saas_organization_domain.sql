-- Establish the SaaS organization boundary without changing existing platform-scoped data.
CREATE TABLE IF NOT EXISTS organizations (
    id         TEXT PRIMARY KEY,
    slug       TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('customer', 'internal')),
    status     TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled', 'archived')),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_organizations_status
    ON organizations (status);
CREATE INDEX IF NOT EXISTS idx_organizations_kind_status
    ON organizations (kind, status);

-- Keep the first internal organization stable for bootstrap/support workflows.
INSERT INTO organizations (id, slug, name, kind, status)
VALUES ('org-internal', 'internal', 'Internal Organization', 'internal', 'active')
ON CONFLICT (id) DO UPDATE
SET slug = EXCLUDED.slug,
    name = EXCLUDED.name,
    kind = EXCLUDED.kind,
    status = EXCLUDED.status,
    updated_at = NOW();

-- Existing roles are platform-scoped until an explicit organization role is
-- created. Keeping the scope in the database prevents a future authorization
-- query from accidentally treating a legacy global role as tenant-local.
ALTER TABLE roles
    ADD COLUMN IF NOT EXISTS scope TEXT;

UPDATE roles
SET scope = 'platform'
WHERE scope IS NULL;

ALTER TABLE roles
    ALTER COLUMN scope SET DEFAULT 'platform',
    ALTER COLUMN scope SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'roles_scope_check'
          AND conrelid = 'roles'::regclass
    ) THEN
        ALTER TABLE roles
            ADD CONSTRAINT roles_scope_check
            CHECK (scope IN ('platform', 'organization'));
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'roles_id_scope_unique'
          AND conrelid = 'roles'::regclass
    ) THEN
        ALTER TABLE roles
            ADD CONSTRAINT roles_id_scope_unique UNIQUE (id, scope);
    END IF;
END
$$;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS user_class TEXT;

-- Only established platform privileges classify a historical account as an
-- internal employee. Role name prefixes are intentionally not trusted because
-- customer administrators may use their own admin-like role names.
UPDATE users AS u
SET user_class = CASE
    WHEN EXISTS (
        SELECT 1
        FROM user_roles AS ur
        INNER JOIN roles AS r ON r.id = ur.role_id
        LEFT JOIN role_permissions AS rp ON rp.role_id = r.id
        LEFT JOIN permissions AS p ON p.id = rp.permission_id
        WHERE ur.user_id = u.id
          AND (r.name = 'super_admin' OR p.name = 'admin.full')
    ) OR EXISTS (
        SELECT 1
        FROM principals AS principal
        INNER JOIN principal_roles AS pr ON pr.principal_id = principal.id
        INNER JOIN roles AS r ON r.id = pr.role_id
        LEFT JOIN role_permissions AS rp ON rp.role_id = r.id
        LEFT JOIN permissions AS p ON p.id = rp.permission_id
        WHERE principal.principal_type = 'user'
          AND principal.ref_id = u.id
          AND (r.name = 'super_admin' OR p.name = 'admin.full')
    ) THEN 'internal_employee'
    ELSE 'external_customer'
END
WHERE u.user_class IS NULL;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM users
        WHERE user_class IS NULL
           OR user_class NOT IN ('internal_employee', 'external_customer')
    ) THEN
        RAISE EXCEPTION 'user_class migration left an invalid or unmapped user';
    END IF;
END
$$;

ALTER TABLE users
    ALTER COLUMN user_class SET DEFAULT 'external_customer',
    ALTER COLUMN user_class SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'users_user_class_check'
          AND conrelid = 'users'::regclass
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT users_user_class_check
            CHECK (user_class IN ('internal_employee', 'external_customer'));
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS organization_memberships (
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    principal_id    TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    status          TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('pending', 'active', 'suspended', 'removed')),
    joined_at       TIMESTAMP NOT NULL DEFAULT NOW(),
    invited_by      TEXT,
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (organization_id, principal_id)
);

CREATE INDEX IF NOT EXISTS idx_organization_memberships_principal
    ON organization_memberships (principal_id, status);
CREATE INDEX IF NOT EXISTS idx_organization_memberships_organization
    ON organization_memberships (organization_id, status);

CREATE TABLE IF NOT EXISTS organization_role_bindings (
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    principal_id    TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    role_id         TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    scope           TEXT NOT NULL DEFAULT 'organization'
        CHECK (scope = 'organization'),
    assigned_at     TIMESTAMP NOT NULL DEFAULT NOW(),
    assigned_by     TEXT,
    PRIMARY KEY (organization_id, principal_id, role_id),
    FOREIGN KEY (organization_id, principal_id)
        REFERENCES organization_memberships (organization_id, principal_id)
        ON DELETE CASCADE,
    FOREIGN KEY (role_id, scope)
        REFERENCES roles (id, scope)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_organization_role_bindings_principal
    ON organization_role_bindings (principal_id, organization_id);
CREATE INDEX IF NOT EXISTS idx_organization_role_bindings_role
    ON organization_role_bindings (role_id, organization_id);

-- Administrators discovered by the explicit migration rule receive an internal
-- membership; inactive principals remain suspended. All other users stay
-- platform-scoped until invited to a tenant.
INSERT INTO organization_memberships (organization_id, principal_id, status, joined_at)
SELECT 'org-internal', p.id,
       CASE WHEN p.active THEN 'active' ELSE 'suspended' END,
       NOW()
FROM principals AS p
INNER JOIN users AS u ON u.id = p.ref_id
WHERE p.principal_type = 'user'
  AND u.user_class = 'internal_employee'
ON CONFLICT (organization_id, principal_id) DO UPDATE
SET status = EXCLUDED.status,
    updated_at = NOW();

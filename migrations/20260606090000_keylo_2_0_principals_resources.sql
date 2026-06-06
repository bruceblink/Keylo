ALTER TABLE roles ADD COLUMN IF NOT EXISTS assignable_to TEXT NOT NULL DEFAULT 'all';
ALTER TABLE roles ADD COLUMN IF NOT EXISTS system BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS principals (
    id TEXT PRIMARY KEY,
    principal_type TEXT NOT NULL,
    subject TEXT UNIQUE NOT NULL,
    ref_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (principal_type, ref_id)
);

CREATE INDEX IF NOT EXISTS idx_principals_type_ref ON principals (principal_type, ref_id);
CREATE INDEX IF NOT EXISTS idx_principals_active ON principals (active);

CREATE TABLE IF NOT EXISTS principal_roles (
    principal_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    assigned_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (principal_id, role_id),
    FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_principal_roles_principal_id ON principal_roles (principal_id);
CREATE INDEX IF NOT EXISTS idx_principal_roles_role_id ON principal_roles (role_id);

CREATE TABLE IF NOT EXISTS resources (
    id TEXT PRIMARY KEY,
    app TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    code TEXT NOT NULL,
    name TEXT NOT NULL,
    parent_id TEXT,
    display_order INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (app, resource_type, code),
    FOREIGN KEY (parent_id) REFERENCES resources(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_resources_parent_id ON resources (parent_id);
CREATE INDEX IF NOT EXISTS idx_resources_lookup ON resources (app, resource_type, code);
CREATE INDEX IF NOT EXISTS idx_resources_active ON resources (active);

CREATE TABLE IF NOT EXISTS resource_permissions (
    resource_id TEXT NOT NULL,
    permission_id TEXT NOT NULL,
    assigned_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (resource_id, permission_id),
    FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_resource_permissions_resource_id ON resource_permissions (resource_id);
CREATE INDEX IF NOT EXISTS idx_resource_permissions_permission_id ON resource_permissions (permission_id);

CREATE TABLE IF NOT EXISTS authorization_audit_logs (
    id TEXT PRIMARY KEY,
    principal_id TEXT,
    decision TEXT NOT NULL,
    permission_name TEXT,
    resource_id TEXT,
    detail TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE SET NULL,
    FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_authorization_audit_principal_id
    ON authorization_audit_logs (principal_id);
CREATE INDEX IF NOT EXISTS idx_authorization_audit_created_at
    ON authorization_audit_logs (created_at);

INSERT INTO principals (id, principal_type, subject, ref_id, display_name, active)
SELECT 'user-' || id, 'user', 'user:' || id, id, username, active
FROM users
ON CONFLICT (principal_type, ref_id) DO UPDATE
SET display_name = EXCLUDED.display_name,
    active = EXCLUDED.active,
    updated_at = NOW();

INSERT INTO principals (id, principal_type, subject, ref_id, display_name, active)
SELECT 'service-' || service_id, 'service', 'service:' || service_id, service_id, name, active
FROM service_clients
ON CONFLICT (principal_type, ref_id) DO UPDATE
SET display_name = EXCLUDED.display_name,
    active = EXCLUDED.active,
    updated_at = NOW();

INSERT INTO principals (id, principal_type, subject, ref_id, display_name, active)
SELECT 'client-' || id, 'client', 'client:' || id, id, name, active
FROM clients
ON CONFLICT (principal_type, ref_id) DO UPDATE
SET display_name = EXCLUDED.display_name,
    active = EXCLUDED.active,
    updated_at = NOW();

INSERT INTO principal_roles (principal_id, role_id, assigned_at)
SELECT p.id, ur.role_id, ur.assigned_at
FROM user_roles ur
INNER JOIN principals p ON p.principal_type = 'user' AND p.ref_id = ur.user_id
ON CONFLICT DO NOTHING;

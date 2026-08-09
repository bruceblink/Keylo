-- Keep delegated organization-management authority separate from the
-- organization role bindings that are not yet part of general authorization.
ALTER TABLE organization_memberships
    ADD COLUMN IF NOT EXISTS management_role TEXT NOT NULL DEFAULT 'member';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'organization_memberships_management_role_check'
          AND conrelid = 'organization_memberships'::regclass
    ) THEN
        ALTER TABLE organization_memberships
            ADD CONSTRAINT organization_memberships_management_role_check
            CHECK (management_role IN ('member', 'admin', 'owner'));
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_organization_memberships_management_role
    ON organization_memberships (organization_id, management_role, status);

-- Resources without an organization remain platform resources. Tenant resources
-- point at one live organization boundary and may reuse platform or other-tenant codes.
ALTER TABLE resources
    ADD COLUMN IF NOT EXISTS organization_id TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'resources_organization_id_fkey'
          AND conrelid = 'resources'::regclass
    ) THEN
        ALTER TABLE resources
            ADD CONSTRAINT resources_organization_id_fkey
            FOREIGN KEY (organization_id)
            REFERENCES organizations(id)
            ON DELETE RESTRICT;
    END IF;
END
$$;

-- PostgreSQL 12 treats NULL values as distinct in a regular UNIQUE constraint.
-- Two partial indexes therefore preserve one platform identity while allowing
-- the same app/type/code tuple once per tenant.
ALTER TABLE resources
    DROP CONSTRAINT IF EXISTS resources_app_resource_type_code_key;

CREATE UNIQUE INDEX IF NOT EXISTS resources_platform_identity_unique
    ON resources (app, resource_type, code)
    WHERE organization_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS resources_organization_identity_unique
    ON resources (organization_id, app, resource_type, code)
    WHERE organization_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_resources_organization_lookup
    ON resources (organization_id, app, resource_type, active);

-- The trigger keeps every tree inside one scope. It checks both assigning a
-- parent and changing a parent's organization so direct SQL cannot create a
-- platform-to-tenant or cross-tenant edge.
CREATE OR REPLACE FUNCTION enforce_resource_organization_tree()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    parent_organization_id TEXT;
BEGIN
    IF NEW.parent_id IS NOT NULL THEN
        SELECT parent.organization_id
        INTO parent_organization_id
        FROM resources AS parent
        WHERE parent.id = NEW.parent_id
        FOR SHARE;

        IF FOUND AND parent_organization_id IS DISTINCT FROM NEW.organization_id THEN
            RAISE EXCEPTION 'resource parent must belong to the same organization scope'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'resources_parent_organization_check';
        END IF;
    END IF;

    IF TG_OP = 'UPDATE'
       AND NEW.organization_id IS DISTINCT FROM OLD.organization_id
       AND EXISTS (
           SELECT 1
           FROM resources AS child
           WHERE child.parent_id = NEW.id
             AND child.organization_id IS DISTINCT FROM NEW.organization_id
           FOR SHARE
       ) THEN
        RAISE EXCEPTION 'resource children must belong to the same organization scope'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'resources_child_organization_check';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_resources_organization_tree ON resources;

CREATE TRIGGER trg_resources_organization_tree
BEFORE INSERT OR UPDATE OF parent_id, organization_id ON resources
FOR EACH ROW
EXECUTE FUNCTION enforce_resource_organization_tree();

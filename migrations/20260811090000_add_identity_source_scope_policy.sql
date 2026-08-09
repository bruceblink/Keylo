-- Make identity-source provisioning policy explicit instead of deriving trust
-- from arbitrary upstream claims or email domains.
ALTER TABLE identity_sources
    ADD COLUMN IF NOT EXISTS allowed_user_class TEXT NOT NULL DEFAULT 'external_customer',
    ADD COLUMN IF NOT EXISTS organization_strategy TEXT NOT NULL DEFAULT 'none',
    ADD COLUMN IF NOT EXISTS organization_id TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'identity_sources_organization_id_fkey'
    ) THEN
        ALTER TABLE identity_sources
            ADD CONSTRAINT identity_sources_organization_id_fkey
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE RESTRICT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'identity_sources_scope_policy_check'
    ) THEN
        ALTER TABLE identity_sources
            ADD CONSTRAINT identity_sources_scope_policy_check CHECK (
                allowed_user_class IN ('external_customer', 'internal_employee')
                AND (
                    (organization_strategy = 'none' AND organization_id IS NULL)
                    OR (organization_strategy = 'fixed' AND organization_id IS NOT NULL)
                )
            );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_identity_sources_organization
    ON identity_sources (organization_id, active, created_at DESC)
    WHERE organization_id IS NOT NULL;

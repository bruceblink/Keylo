-- A NULL organization_id preserves existing platform-scoped sessions. A session
-- with an organization_id is pinned to that tenant and must never become
-- platform-scoped if the organization is removed.
ALTER TABLE refresh_sessions
    ADD COLUMN IF NOT EXISTS organization_id TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'refresh_sessions_organization_id_fkey'
          AND conrelid = 'refresh_sessions'::regclass
    ) THEN
        ALTER TABLE refresh_sessions
            ADD CONSTRAINT refresh_sessions_organization_id_fkey
            FOREIGN KEY (organization_id)
            REFERENCES organizations(id)
            ON DELETE RESTRICT;
    END IF;
END
$$;

-- Organization-wide revocation and active tenant session listings both start
-- with this scope, while platform sessions are intentionally left out.
CREATE INDEX IF NOT EXISTS idx_refresh_sessions_organization_active
    ON refresh_sessions (organization_id, issued_at DESC)
    WHERE organization_id IS NOT NULL AND revoked_at IS NULL;

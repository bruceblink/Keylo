-- Keep the signed tenant context on authorization decisions. This is not a
-- foreign key because audit evidence must survive a later archival or repair.
ALTER TABLE authorization_audit_logs
    ADD COLUMN IF NOT EXISTS organization_id TEXT;

CREATE INDEX IF NOT EXISTS idx_authorization_audit_organization_created
    ON authorization_audit_logs (organization_id, created_at DESC);

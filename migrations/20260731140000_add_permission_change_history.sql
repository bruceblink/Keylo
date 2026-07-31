CREATE TABLE IF NOT EXISTS permission_change_history (
    id TEXT PRIMARY KEY,
    permission_id TEXT NOT NULL,
    version BIGINT NOT NULL,
    actor TEXT,
    change_reason TEXT,
    before_state JSONB NOT NULL,
    after_state JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (permission_id, version)
);

CREATE INDEX IF NOT EXISTS idx_permission_change_history_permission_version
    ON permission_change_history (permission_id, version DESC);

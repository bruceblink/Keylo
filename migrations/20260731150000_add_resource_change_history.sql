CREATE TABLE IF NOT EXISTS resource_change_history (
    id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL,
    version BIGINT NOT NULL,
    actor TEXT,
    change_reason TEXT,
    before_state JSONB NOT NULL,
    after_state JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (resource_id, version)
);

CREATE INDEX IF NOT EXISTS idx_resource_change_history_resource_version
    ON resource_change_history (resource_id, version DESC);

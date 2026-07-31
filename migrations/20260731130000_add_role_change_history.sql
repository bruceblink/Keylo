CREATE TABLE IF NOT EXISTS role_change_history (
    id TEXT PRIMARY KEY,
    role_id TEXT NOT NULL,
    version BIGINT NOT NULL,
    actor TEXT,
    change_reason TEXT,
    before_state JSONB NOT NULL,
    after_state JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (role_id, version)
);

CREATE INDEX IF NOT EXISTS idx_role_change_history_role_version
    ON role_change_history (role_id, version DESC);

CREATE TABLE IF NOT EXISTS external_user_mappings (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    external_user_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (provider, external_user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_external_user_mappings_provider
    ON external_user_mappings(provider);

CREATE INDEX IF NOT EXISTS idx_external_user_mappings_user_id
    ON external_user_mappings(user_id);

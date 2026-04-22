-- Additional performance indexes for high-frequency query patterns.
-- This migration only adds indexes and does not modify existing schema objects.

-- clients: optimize admin-client existence checks and admin client listing
CREATE INDEX IF NOT EXISTS idx_clients_active_admin_client
    ON clients (is_admin_client)
    WHERE active = TRUE AND is_admin_client = TRUE;

CREATE INDEX IF NOT EXISTS idx_clients_updated_at_desc
    ON clients (updated_at DESC);

-- users: optimize paginated user listing ordered by creation time
CREATE INDEX IF NOT EXISTS idx_users_created_at_desc
    ON users (created_at DESC);

-- service_clients: optimize management listing ordered by creation time
CREATE INDEX IF NOT EXISTS idx_service_clients_created_at_desc
    ON service_clients (created_at DESC);

-- oauth_providers: optimize active provider listing and lookup by active+name
CREATE INDEX IF NOT EXISTS idx_oauth_providers_active_name
    ON oauth_providers (name)
    WHERE active = TRUE;

-- user_oauth_accounts: optimize per-user account listing with ordering
CREATE INDEX IF NOT EXISTS idx_user_oauth_accounts_user_id_linked_at_desc
    ON user_oauth_accounts (user_id, linked_at DESC);

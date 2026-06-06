ALTER TABLE refresh_sessions ADD COLUMN IF NOT EXISTS login_ip TEXT;
ALTER TABLE refresh_sessions ADD COLUMN IF NOT EXISTS user_agent TEXT;

CREATE INDEX IF NOT EXISTS idx_refresh_sessions_login_ip
    ON refresh_sessions (login_ip);

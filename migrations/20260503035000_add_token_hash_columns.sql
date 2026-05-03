CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS token_hash TEXT;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS token_hash TEXT;
ALTER TABLE blacklisted_tokens ADD COLUMN IF NOT EXISTS token_hash TEXT;

UPDATE sessions SET token_hash = encode(digest(token, 'sha256'), 'hex') WHERE token_hash IS NULL;
UPDATE refresh_tokens SET token_hash = encode(digest(token, 'sha256'), 'hex') WHERE token_hash IS NULL;
UPDATE blacklisted_tokens SET token_hash = encode(digest(token, 'sha256'), 'hex') WHERE token_hash IS NULL;

ALTER TABLE sessions ALTER COLUMN token_hash SET NOT NULL;
ALTER TABLE refresh_tokens ALTER COLUMN token_hash SET NOT NULL;
ALTER TABLE blacklisted_tokens ALTER COLUMN token_hash SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE UNIQUE INDEX IF NOT EXISTS idx_blacklisted_tokens_token_hash ON blacklisted_tokens(token_hash);

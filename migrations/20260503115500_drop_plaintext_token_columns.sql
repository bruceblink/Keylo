DROP INDEX IF EXISTS idx_refresh_tokens_token;

ALTER TABLE sessions DROP COLUMN IF EXISTS token;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS token;
ALTER TABLE blacklisted_tokens DROP COLUMN IF EXISTS token;

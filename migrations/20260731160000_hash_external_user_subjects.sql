-- External subjects are stable lookup keys, not application-visible profile data.
-- pgcrypto is required only for this one-time conversion of existing mappings.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE external_user_mappings
    ADD COLUMN IF NOT EXISTS external_user_id_hashed BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE external_user_mappings
SET external_user_id = encode(digest(external_user_id, 'sha256'), 'hex'),
    external_user_id_hashed = TRUE
WHERE external_user_id_hashed = FALSE;

ALTER TABLE external_user_mappings
    DROP COLUMN IF EXISTS external_user_id_hashed;

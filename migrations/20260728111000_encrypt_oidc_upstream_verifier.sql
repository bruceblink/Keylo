ALTER TABLE oidc_upstream_authorizations
    RENAME COLUMN code_verifier_hash TO code_verifier_encrypted;

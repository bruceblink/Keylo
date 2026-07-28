use anyhow::Result;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::OidcUpstreamAuthorizationState;

#[derive(Debug, Clone)]
pub struct ConsumedOidcUpstreamAuthorization {
    pub source_id: String,
    pub nonce_hash: String,
    pub code_verifier_hash: String,
}

fn opaque_hash(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// Persist an opaque upstream authorization transaction without storing replayable secrets.
pub async fn create_oidc_upstream_authorization(
    pool: &PgPool,
    source_id: &str,
    authorization: &OidcUpstreamAuthorizationState,
    expires_at: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO oidc_upstream_authorizations
         (id, state_hash, source_id, nonce_hash, code_verifier_hash, expires_at)
         VALUES ($1, $2, $3, $4, $5, to_timestamp($6))",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(opaque_hash(&authorization.state))
    .bind(source_id)
    .bind(opaque_hash(&authorization.nonce))
    .bind(opaque_hash(&authorization.code_verifier))
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Atomically consume a callback state so it cannot be replayed after token exchange starts.
pub async fn consume_oidc_upstream_authorization(
    pool: &PgPool,
    state: &str,
) -> Result<Option<ConsumedOidcUpstreamAuthorization>> {
    let row = sqlx::query_as::<_, (String, String, String)>(
        "UPDATE oidc_upstream_authorizations SET consumed_at = NOW()
         WHERE state_hash = $1 AND consumed_at IS NULL AND expires_at > NOW()
         RETURNING source_id, nonce_hash, code_verifier_hash",
    )
    .bind(opaque_hash(state))
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(source_id, nonce_hash, code_verifier_hash)| ConsumedOidcUpstreamAuthorization {
            source_id,
            nonce_hash,
            code_verifier_hash,
        },
    ))
}

/// Compare a callback value with its retained hash without retaining plaintext state.
pub fn opaque_value_matches(value: &str, expected_hash: &str) -> bool {
    opaque_hash(value) == expected_hash
}

#[cfg(test)]
mod tests {
    use super::{opaque_hash, opaque_value_matches};

    #[test]
    fn opaque_authorization_values_are_verified_without_plaintext_storage() {
        let hash = opaque_hash("one-time-value");
        assert!(opaque_value_matches("one-time-value", &hash));
        assert!(!opaque_value_matches("other-value", &hash));
        assert!(!hash.contains("one-time-value"));
    }
}

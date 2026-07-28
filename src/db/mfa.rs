use crate::models::MfaTotpCredential;
use anyhow::Result;
use sqlx::PgPool;

/// Create or replace an unverified enrollment seed for a user.
pub async fn save_pending_totp_credential(
    pool: &PgPool,
    user_id: &str,
    encrypted_seed: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO mfa_totp_credentials (user_id, encrypted_seed)
         VALUES ($1, $2)
         ON CONFLICT (user_id) DO UPDATE
         SET encrypted_seed = EXCLUDED.encrypted_seed,
             enabled_at = NULL,
             last_verified_step = NULL,
             updated_at = NOW()",
    )
    .bind(user_id)
    .bind(encrypted_seed)
    .execute(pool)
    .await?;

    Ok(())
}

/// Load a user's MFA enrollment state for verification or administration.
pub async fn get_totp_credential(
    pool: &PgPool,
    user_id: &str,
) -> Result<Option<MfaTotpCredential>> {
    Ok(sqlx::query_as(
        "SELECT user_id, encrypted_seed, enabled_at, last_verified_step, created_at, updated_at
         FROM mfa_totp_credentials WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?)
}

/// Mark a credential enabled only after a successful TOTP verification.
pub async fn enable_totp_credential(pool: &PgPool, user_id: &str, step: i64) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE mfa_totp_credentials
         SET enabled_at = NOW(), last_verified_step = $2, updated_at = NOW()
         WHERE user_id = $1 AND enabled_at IS NULL",
    )
    .bind(user_id)
    .bind(step)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Remove all TOTP state; callers must enforce recent MFA before using it on enabled accounts.
pub async fn delete_totp_credential(pool: &PgPool, user_id: &str) -> Result<bool> {
    Ok(
        sqlx::query("DELETE FROM mfa_totp_credentials WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await?
            .rows_affected()
            > 0,
    )
}

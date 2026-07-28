use crate::models::{normalize_recovery_code, MfaTotpCredential, RECOVERY_CODE_COUNT};
use anyhow::{bail, Result};
use bcrypt::{hash, verify, DEFAULT_COST};
use sqlx::PgPool;
use uuid::Uuid;

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

/// Enable a verified TOTP seed and replace recovery codes in one database transaction.
pub async fn enable_totp_credential_with_recovery_codes(
    pool: &PgPool,
    user_id: &str,
    step: i64,
    recovery_codes: &[String],
) -> Result<bool> {
    if recovery_codes.len() != RECOVERY_CODE_COUNT {
        bail!("expected exactly {RECOVERY_CODE_COUNT} recovery codes");
    }
    let mut hashes = Vec::with_capacity(recovery_codes.len());
    for code in recovery_codes {
        let normalized = normalize_recovery_code(code)
            .ok_or_else(|| anyhow::anyhow!("recovery code has an invalid format"))?;
        hashes.push(hash(normalized, DEFAULT_COST)?);
    }

    let mut transaction = pool.begin().await?;
    let enabled = sqlx::query(
        "UPDATE mfa_totp_credentials
         SET enabled_at = NOW(), last_verified_step = $2, updated_at = NOW()
         WHERE user_id = $1 AND enabled_at IS NULL",
    )
    .bind(user_id)
    .bind(step)
    .execute(&mut *transaction)
    .await?
    .rows_affected()
        > 0;
    if !enabled {
        transaction.rollback().await?;
        return Ok(false);
    }

    sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
    for code_hash in hashes {
        sqlx::query(
            "INSERT INTO mfa_recovery_codes (id, user_id, code_hash)
             VALUES ($1, $2, $3)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(code_hash)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;

    Ok(true)
}

/// Atomically mark a matching recovery code used; a concurrent second use always fails.
pub async fn consume_recovery_code(pool: &PgPool, user_id: &str, code: &str) -> Result<bool> {
    let normalized = match normalize_recovery_code(code) {
        Some(code) => code,
        None => return Ok(false),
    };
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT id, code_hash FROM mfa_recovery_codes
         WHERE user_id = $1 AND used_at IS NULL",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    for (id, code_hash) in rows {
        if verify(&normalized, &code_hash)? {
            return Ok(sqlx::query(
                "UPDATE mfa_recovery_codes SET used_at = NOW()
                 WHERE id = $1 AND used_at IS NULL",
            )
            .bind(id)
            .execute(pool)
            .await?
            .rows_affected()
                > 0);
        }
    }

    Ok(false)
}

/// Consume a valid TOTP time step and persist a short-lived proof for the current access token.
pub async fn consume_totp_step_and_record_recent_verification(
    pool: &PgPool,
    user_id: &str,
    step: i64,
    token_jti: &str,
    expires_at: i64,
) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    let consumed = sqlx::query(
        "UPDATE mfa_totp_credentials
         SET last_verified_step = $2, updated_at = NOW()
         WHERE user_id = $1
           AND enabled_at IS NOT NULL
           AND (last_verified_step IS NULL OR last_verified_step < $2)",
    )
    .bind(user_id)
    .bind(step)
    .execute(&mut *transaction)
    .await?
    .rows_affected()
        > 0;
    if !consumed {
        transaction.rollback().await?;
        return Ok(false);
    }

    save_recent_verification(&mut transaction, user_id, token_jti, expires_at).await?;
    transaction.commit().await?;
    Ok(true)
}

/// Consume a recovery code and create the associated token-bound MFA proof atomically.
pub async fn consume_recovery_code_and_record_recent_verification(
    pool: &PgPool,
    user_id: &str,
    code: &str,
    token_jti: &str,
    expires_at: i64,
) -> Result<bool> {
    let normalized = match normalize_recovery_code(code) {
        Some(code) => code,
        None => return Ok(false),
    };
    let mut transaction = pool.begin().await?;
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT id, code_hash FROM mfa_recovery_codes
         WHERE user_id = $1 AND used_at IS NULL FOR UPDATE",
    )
    .bind(user_id)
    .fetch_all(&mut *transaction)
    .await?;

    let mut matching_id = None;
    for (id, code_hash) in rows {
        if verify(&normalized, &code_hash)? {
            matching_id = Some(id);
            break;
        }
    }
    let Some(id) = matching_id else {
        transaction.rollback().await?;
        return Ok(false);
    };
    sqlx::query("UPDATE mfa_recovery_codes SET used_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&mut *transaction)
        .await?;
    save_recent_verification(&mut transaction, user_id, token_jti, expires_at).await?;
    transaction.commit().await?;

    Ok(true)
}

/// Check whether this exact user access token has a still-valid MFA confirmation.
pub async fn has_recent_mfa_verification(
    pool: &PgPool,
    user_id: &str,
    token_jti: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
             SELECT 1 FROM mfa_recent_verifications
             WHERE user_id = $1 AND token_jti = $2 AND expires_at > NOW()
         )",
    )
    .bind(user_id)
    .bind(token_jti)
    .fetch_one(pool)
    .await?)
}

/// Insert or extend the proof within an existing transaction so factor consumption remains atomic.
async fn save_recent_verification(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &str,
    token_jti: &str,
    expires_at: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO mfa_recent_verifications (user_id, token_jti, expires_at)
         VALUES ($1, $2, to_timestamp($3))
         ON CONFLICT (user_id, token_jti) DO UPDATE
         SET verified_at = NOW(), expires_at = EXCLUDED.expires_at",
    )
    .bind(user_id)
    .bind(token_jti)
    .bind(expires_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
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

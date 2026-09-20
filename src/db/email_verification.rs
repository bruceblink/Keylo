use crate::db::token_hash;
use anyhow::Result;
use chrono::Utc;
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedEmailVerificationToken {
    /// Database identifier used only to revoke a token if delivery fails.
    pub id: String,
    /// Snapshot of the user's email at issue time; it binds the token to the current address.
    pub email: String,
    /// One-time value returned only to the mail provider, never to an HTTP response or audit log.
    pub token: String,
    /// Unix timestamp after which the token is rejected by the consume transaction.
    pub expires_at: i64,
}

/// Result of the atomic consume operation; invalid states are deliberately collapsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumeEmailVerificationTokenResult {
    /// The token transitioned to consumed and the user was marked verified.
    Verified { user_id: String },
    /// Unknown, expired, revoked, consumed, inactive, or email-mismatched token.
    Invalid,
}

/// Issue one short-lived token for the user's current email and revoke older pending tokens.
///
/// The user row is locked before eligibility is checked. Within one transaction,
/// older pending rows are revoked and only the SHA-256 token digest is stored;
/// the plaintext token exists only in the returned value for immediate delivery.
/// A missing, inactive, or already verified user returns `None` without creating
/// a row. Dropping the transaction future rolls back both revocation and insert.
pub async fn issue_email_verification_token(
    pool: &PgPool,
    user_id: &str,
    lifetime_seconds: i64,
) -> Result<Option<IssuedEmailVerificationToken>> {
    let mut transaction = pool.begin().await?;
    let user =
        sqlx::query("SELECT email, email_verified, active FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *transaction)
            .await?;
    let Some(user) = user else {
        transaction.commit().await?;
        return Ok(None);
    };

    let email: String = user.get("email");
    let email_verified: bool = user.get("email_verified");
    let active: bool = user.get("active");
    if !active || email_verified {
        transaction.commit().await?;
        return Ok(None);
    }

    let token = Uuid::new_v4().simple().to_string();
    let token_id = Uuid::new_v4().to_string();
    let expires_at = Utc::now().timestamp() + lifetime_seconds.max(1);

    sqlx::query(
        "UPDATE email_verification_tokens
         SET revoked_at = COALESCE(revoked_at, NOW())
         WHERE user_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *transaction)
    .await?;

    sqlx::query(
        "INSERT INTO email_verification_tokens
            (id, user_id, email_snapshot, token_hash, expires_at)
         VALUES ($1, $2, $3, $4, to_timestamp($5))",
    )
    .bind(&token_id)
    .bind(user_id)
    .bind(&email)
    .bind(token_hash(&token))
    .bind(expires_at)
    .execute(&mut *transaction)
    .await?;

    transaction.commit().await?;
    Ok(Some(IssuedEmailVerificationToken {
        id: token_id,
        email,
        token,
        expires_at,
    }))
}

/// Consume a token once while checking its expiry, account state, and current email snapshot.
///
/// The token digest lookup locks both the token row and the account row. The
/// transaction validates every state predicate before setting `consumed_at`;
/// therefore concurrent consumers cannot both verify the account. Invalid
/// pending rows are revoked to prevent repeated work, while unknown values
/// produce the same `Invalid` result. Success updates `users.email_verified`
/// and writes a redacted audit detail in the same transaction. Database errors
/// are returned to the caller and transaction cancellation rolls back all state.
pub async fn consume_email_verification_token(
    pool: &PgPool,
    token: &str,
) -> Result<ConsumeEmailVerificationTokenResult> {
    let mut transaction = pool.begin().await?;
    let record = sqlx::query(
        "SELECT email_token.id,
                email_token.user_id,
                email_token.email_snapshot,
                email_token.expires_at,
                email_token.consumed_at,
                email_token.revoked_at,
                account.email,
                account.email_verified,
                account.active
         FROM email_verification_tokens AS email_token
         INNER JOIN users AS account ON account.id = email_token.user_id
         WHERE email_token.token_hash = $1
         FOR UPDATE OF email_token, account",
    )
    .bind(token_hash(token))
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(record) = record else {
        transaction.commit().await?;
        return Ok(ConsumeEmailVerificationTokenResult::Invalid);
    };

    let token_id: String = record.get("id");
    let user_id: String = record.get("user_id");
    let email_snapshot: String = record.get("email_snapshot");
    let expires_at: chrono::NaiveDateTime = record.get("expires_at");
    let consumed_at: Option<chrono::NaiveDateTime> = record.get("consumed_at");
    let revoked_at: Option<chrono::NaiveDateTime> = record.get("revoked_at");
    let email: String = record.get("email");
    let email_verified: bool = record.get("email_verified");
    let active: bool = record.get("active");

    let invalid = consumed_at.is_some()
        || revoked_at.is_some()
        || expires_at <= Utc::now().naive_utc()
        || !active
        || email != email_snapshot;
    if invalid {
        if consumed_at.is_none() && revoked_at.is_none() {
            sqlx::query(
                "UPDATE email_verification_tokens
                 SET revoked_at = COALESCE(revoked_at, NOW())
                 WHERE id = $1",
            )
            .bind(&token_id)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        return Ok(ConsumeEmailVerificationTokenResult::Invalid);
    }

    sqlx::query("UPDATE email_verification_tokens SET consumed_at = NOW() WHERE id = $1")
        .bind(&token_id)
        .execute(&mut *transaction)
        .await?;

    if !email_verified {
        sqlx::query("UPDATE users SET email_verified = TRUE, updated_at = NOW() WHERE id = $1")
            .bind(&user_id)
            .execute(&mut *transaction)
            .await?;

        sqlx::query(
            "INSERT INTO audit_logs (id, event_type, actor, detail)
             VALUES ($1, $2, NULL, $3)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind("user.email_verified")
        .bind(format!("user_id={user_id}; method=email_token"))
        .execute(&mut *transaction)
        .await?;
    }

    transaction.commit().await?;
    Ok(ConsumeEmailVerificationTokenResult::Verified { user_id })
}

/// Revoke a token after delivery fails so an undelivered token cannot be reused.
///
/// The update is conditional on both `consumed_at` and `revoked_at` being empty,
/// making retries idempotent and preventing a failed delivery path from altering
/// a token that was already consumed by another operation.
pub async fn revoke_email_verification_token(pool: &PgPool, token_id: &str) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE email_verification_tokens
         SET revoked_at = COALESCE(revoked_at, NOW())
         WHERE id = $1 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(token_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

use crate::db::token_hash;
use anyhow::Result;
use bcrypt::hash;
use chrono::Utc;
use sqlx::{PgPool, Row};
use uuid::Uuid;

const PASSWORD_HASH_COST: u32 = bcrypt::DEFAULT_COST;

/// A password-reset token that is safe to pass to the mail boundary.
///
/// `token` is the only plaintext secret and is returned exactly once to the
/// caller for delivery. The database stores only `token_hash`; `email` binds
/// the proof to the address that was verified when it was issued, and
/// `expires_at` bounds the replay window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedPasswordResetToken {
    /// Database identifier used to revoke an undelivered token.
    pub id: String,
    /// Current verified email address captured at issue time.
    pub email: String,
    /// One-time plaintext proof; never returned by an HTTP response or audit log.
    pub token: String,
    /// Unix timestamp after which the token is invalid.
    pub expires_at: i64,
}

/// Result of atomically consuming a password-reset proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumePasswordResetTokenResult {
    /// Password changed and all existing long-lived user sessions were revoked.
    Reset {
        user_id: String,
        revoked_refresh_sessions: u64,
        revoked_browser_sessions: u64,
    },
    /// Unknown, expired, revoked, consumed, inactive, or email-mismatched proof.
    Invalid,
}

/// Find an eligible local account without exposing account existence to callers.
///
/// Email is checked before username so an accidental value collision cannot
/// select an arbitrary account. Only active, email-verified accounts with a
/// local password can enter this flow; external-only identities must use their
/// upstream provider instead.
async fn eligible_user(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    identifier: &str,
) -> Result<Option<(String, String)>> {
    let by_email = sqlx::query(
        "SELECT id, email FROM users
         WHERE email = $1 AND active = TRUE AND email_verified = TRUE
           AND password_hash IS NOT NULL
         LIMIT 1 FOR UPDATE",
    )
    .bind(identifier)
    .fetch_optional(&mut **transaction)
    .await?;
    if let Some(row) = by_email {
        return Ok(Some((row.get("id"), row.get("email"))));
    }

    let by_username = sqlx::query(
        "SELECT id, email FROM users
         WHERE username = $1 AND active = TRUE AND email_verified = TRUE
           AND password_hash IS NOT NULL
         LIMIT 1 FOR UPDATE",
    )
    .bind(identifier)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(by_username.map(|row| (row.get("id"), row.get("email"))))
}

/// Issue one short-lived proof and revoke older pending proofs for the account.
///
/// The account row is locked before eligibility is evaluated. Revocation and
/// insertion commit together, so concurrent requests leave at most one usable
/// proof. The plaintext value is generated only after the account is known and
/// is never persisted. A missing or ineligible account returns `None` so the
/// HTTP layer can keep the public response identical for known and unknown
/// identifiers.
pub async fn issue_password_reset_token(
    pool: &PgPool,
    identifier: &str,
    lifetime_seconds: i64,
) -> Result<Option<IssuedPasswordResetToken>> {
    let mut transaction = pool.begin().await?;
    let Some((user_id, email)) = eligible_user(&mut transaction, identifier).await? else {
        transaction.commit().await?;
        return Ok(None);
    };

    let token = Uuid::new_v4().simple().to_string();
    let token_id = Uuid::new_v4().to_string();
    let expires_at = Utc::now().timestamp() + lifetime_seconds.max(1);

    sqlx::query(
        "UPDATE password_reset_tokens
         SET revoked_at = COALESCE(revoked_at, NOW())
         WHERE user_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(&user_id)
    .execute(&mut *transaction)
    .await?;

    sqlx::query(
        "INSERT INTO password_reset_tokens
            (id, user_id, email_snapshot, token_hash, expires_at)
         VALUES ($1, $2, $3, $4, to_timestamp($5))",
    )
    .bind(&token_id)
    .bind(&user_id)
    .bind(&email)
    .bind(token_hash(&token))
    .bind(expires_at)
    .execute(&mut *transaction)
    .await?;

    transaction.commit().await?;
    Ok(Some(IssuedPasswordResetToken {
        id: token_id,
        email,
        token,
        expires_at,
    }))
}

/// Consume a reset proof and replace the password in one failure-closed transaction.
///
/// The token and account rows are locked before any state transition, so two
/// concurrent confirmations cannot both change the credential. The current
/// email, verified flag, account status, expiry, and one-time state are checked
/// against the snapshot. A valid reset sets `password_change_required = TRUE`,
/// revokes refresh and OIDC browser sessions, revokes sibling pending proofs,
/// and writes a token-free audit record before commit. Any database or hashing
/// failure rolls back the entire transition; cancellation therefore cannot leave
/// a changed password with live old sessions.
pub async fn consume_password_reset_token(
    pool: &PgPool,
    token: &str,
    new_password: &str,
) -> Result<ConsumePasswordResetTokenResult> {
    let mut transaction = pool.begin().await?;
    let record = sqlx::query(
        "SELECT reset_token.id,
                reset_token.user_id,
                reset_token.email_snapshot,
                reset_token.expires_at,
                reset_token.consumed_at,
                reset_token.revoked_at,
                account.email,
                account.email_verified,
                account.active,
                account.password_hash
         FROM password_reset_tokens AS reset_token
         INNER JOIN users AS account ON account.id = reset_token.user_id
         WHERE reset_token.token_hash = $1
         FOR UPDATE OF reset_token, account",
    )
    .bind(token_hash(token))
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(record) = record else {
        transaction.commit().await?;
        return Ok(ConsumePasswordResetTokenResult::Invalid);
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
    let password_hash: Option<String> = record.get("password_hash");

    let invalid = consumed_at.is_some()
        || revoked_at.is_some()
        || expires_at <= Utc::now().naive_utc()
        || !active
        || !email_verified
        || password_hash.is_none()
        || email != email_snapshot;
    if invalid {
        if consumed_at.is_none() && revoked_at.is_none() {
            sqlx::query(
                "UPDATE password_reset_tokens
                 SET revoked_at = COALESCE(revoked_at, NOW())
                 WHERE id = $1",
            )
            .bind(&token_id)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        return Ok(ConsumePasswordResetTokenResult::Invalid);
    }

    let password_hash = hash(new_password, PASSWORD_HASH_COST)?;
    sqlx::query("UPDATE password_reset_tokens SET consumed_at = NOW() WHERE id = $1")
        .bind(&token_id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "UPDATE users
         SET password_hash = $2, password_change_required = TRUE, updated_at = NOW()
         WHERE id = $1",
    )
    .bind(&user_id)
    .bind(password_hash)
    .execute(&mut *transaction)
    .await?;

    let revoked_refresh_sessions = sqlx::query(
        "UPDATE refresh_sessions
         SET revoked_at = COALESCE(revoked_at, NOW()),
             revoke_reason = COALESCE(revoke_reason, 'password_reset')
         WHERE principal_id IN (
             SELECT id FROM principals WHERE principal_type = 'user' AND ref_id = $1
         ) AND revoked_at IS NULL",
    )
    .bind(&user_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    let revoked_browser_sessions = sqlx::query(
        "UPDATE oidc_browser_sessions
         SET revoked_at = COALESCE(revoked_at, NOW())
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(&user_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    sqlx::query(
        "UPDATE password_reset_tokens
         SET revoked_at = COALESCE(revoked_at, NOW())
         WHERE user_id = $1 AND id <> $2 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(&user_id)
    .bind(&token_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO audit_logs (id, event_type, actor, detail)
         VALUES ($1, $2, NULL, $3)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind("user.password_reset")
    .bind(format!(
        "user_id={}; revoked_refresh_sessions={}; revoked_oidc_browser_sessions={}",
        user_id, revoked_refresh_sessions, revoked_browser_sessions
    ))
    .execute(&mut *transaction)
    .await?;

    transaction.commit().await?;
    Ok(ConsumePasswordResetTokenResult::Reset {
        user_id,
        revoked_refresh_sessions,
        revoked_browser_sessions,
    })
}

/// Revoke a reset proof after a delivery failure without touching consumed proofs.
pub async fn revoke_password_reset_token(pool: &PgPool, token_id: &str) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE password_reset_tokens
         SET revoked_at = COALESCE(revoked_at, NOW())
         WHERE id = $1 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(token_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

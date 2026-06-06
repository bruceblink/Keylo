use anyhow::Result;
use sqlx::{PgPool, Row};

use crate::db::token_hash;

#[derive(Debug, Clone, serde::Serialize)]
pub struct RefreshSessionInfo {
    pub id: String,
    pub principal_id: String,
    pub client_id: String,
    pub current_access_jti: String,
    pub issued_at: i64,
    pub rotated_at: Option<i64>,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub revoke_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedRefreshSession {
    pub session_id: String,
    pub principal_id: String,
    pub client_id: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumeRefreshSessionResult {
    Consumed(ConsumedRefreshSession),
    NotFound,
    Replayed { session_id: String },
}

pub struct CreateRefreshSessionParams<'a> {
    pub session_id: &'a str,
    pub principal_id: &'a str,
    pub client_id: &'a str,
    pub refresh_token_id: &'a str,
    pub refresh_token: &'a str,
    pub access_jti: &'a str,
    pub expires_at: i64,
}

pub async fn create_refresh_session(
    pool: &PgPool,
    params: CreateRefreshSessionParams<'_>,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    let refresh_token_hash = token_hash(params.refresh_token);

    sqlx::query(
        r#"
        INSERT INTO refresh_sessions
            (id, principal_id, client_id, current_refresh_token_id, current_access_jti, expires_at)
        VALUES ($1, $2, $3, $4, $5, to_timestamp($6))
        "#,
    )
    .bind(params.session_id)
    .bind(params.principal_id)
    .bind(params.client_id)
    .bind(params.refresh_token_id)
    .bind(params.access_jti)
    .bind(params.expires_at)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO refresh_session_tokens (token_id, session_id, token_hash, expires_at)
        VALUES ($1, $2, $3, to_timestamp($4))
        "#,
    )
    .bind(params.refresh_token_id)
    .bind(params.session_id)
    .bind(refresh_token_hash)
    .bind(params.expires_at)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

pub async fn consume_and_rotate_refresh_session(
    pool: &PgPool,
    refresh_token: &str,
    new_refresh_token_id: &str,
    new_refresh_token: &str,
    new_access_jti: &str,
) -> Result<ConsumeRefreshSessionResult> {
    let mut tx = pool.begin().await?;
    let refresh_token_hash = token_hash(refresh_token);
    let new_refresh_token_hash = token_hash(new_refresh_token);

    let row = sqlx::query(
        r#"
        SELECT
            rst.token_id,
            rst.session_id,
            rst.consumed_at,
            rst.revoked_at AS token_revoked_at,
            rst.expires_at > NOW() AS token_active,
            rs.principal_id,
            rs.client_id,
            rs.revoked_at AS session_revoked_at,
            rs.expires_at > NOW() AS session_active,
            extract(epoch from rs.expires_at)::bigint AS session_expires_at
        FROM refresh_session_tokens rst
        INNER JOIN refresh_sessions rs ON rs.id = rst.session_id
        WHERE rst.token_hash = $1
        FOR UPDATE OF rst, rs
        "#,
    )
    .bind(refresh_token_hash)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(row) = row else {
        tx.commit().await?;
        return Ok(ConsumeRefreshSessionResult::NotFound);
    };

    let session_id: String = row.get("session_id");
    let token_active: bool = row.get("token_active");
    let session_active: bool = row.get("session_active");
    let token_consumed = row
        .get::<Option<chrono::NaiveDateTime>, _>("consumed_at")
        .is_some();
    let token_revoked = row
        .get::<Option<chrono::NaiveDateTime>, _>("token_revoked_at")
        .is_some();
    let session_revoked = row
        .get::<Option<chrono::NaiveDateTime>, _>("session_revoked_at")
        .is_some();

    if !token_active || !session_active {
        tx.commit().await?;
        return Ok(ConsumeRefreshSessionResult::NotFound);
    }

    if token_consumed || token_revoked || session_revoked {
        sqlx::query(
            r#"
            UPDATE refresh_sessions
            SET revoked_at = COALESCE(revoked_at, NOW()),
                revoke_reason = COALESCE(revoke_reason, 'refresh_token_replay')
            WHERE id = $1
            "#,
        )
        .bind(&session_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        return Ok(ConsumeRefreshSessionResult::Replayed { session_id });
    }

    let session_expires_at: i64 = row.get("session_expires_at");
    let principal_id: String = row.get("principal_id");
    let client_id: String = row.get("client_id");

    sqlx::query(
        r#"
        UPDATE refresh_session_tokens
        SET consumed_at = NOW()
        WHERE token_hash = $1
        "#,
    )
    .bind(token_hash(refresh_token))
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO refresh_session_tokens (token_id, session_id, token_hash, expires_at)
        VALUES ($1, $2, $3, to_timestamp($4))
        "#,
    )
    .bind(new_refresh_token_id)
    .bind(&session_id)
    .bind(new_refresh_token_hash)
    .bind(session_expires_at)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        UPDATE refresh_sessions
        SET current_refresh_token_id = $2,
            current_access_jti = $3,
            rotated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(&session_id)
    .bind(new_refresh_token_id)
    .bind(new_access_jti)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(ConsumeRefreshSessionResult::Consumed(
        ConsumedRefreshSession {
            session_id,
            principal_id,
            client_id,
            expires_at: session_expires_at,
        },
    ))
}

pub async fn revoke_refresh_session(
    pool: &PgPool,
    session_id: &str,
    reason: Option<&str>,
) -> Result<bool> {
    let result = sqlx::query(
        r#"
        UPDATE refresh_sessions
        SET revoked_at = COALESCE(revoked_at, NOW()),
            revoke_reason = COALESCE(revoke_reason, $2)
        WHERE id = $1
        "#,
    )
    .bind(session_id)
    .bind(reason)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn list_refresh_sessions_for_principal(
    pool: &PgPool,
    principal_id: &str,
    include_revoked: bool,
) -> Result<Vec<RefreshSessionInfo>> {
    let rows = sqlx::query(
        r#"
        SELECT
            id,
            principal_id,
            client_id,
            current_access_jti,
            extract(epoch from issued_at)::bigint AS issued_at,
            extract(epoch from rotated_at)::bigint AS rotated_at,
            extract(epoch from expires_at)::bigint AS expires_at,
            extract(epoch from revoked_at)::bigint AS revoked_at,
            revoke_reason
        FROM refresh_sessions
        WHERE principal_id = $1
          AND ($2 OR revoked_at IS NULL)
        ORDER BY issued_at DESC
        "#,
    )
    .bind(principal_id)
    .bind(include_revoked)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| RefreshSessionInfo {
            id: row.get("id"),
            principal_id: row.get("principal_id"),
            client_id: row.get("client_id"),
            current_access_jti: row.get("current_access_jti"),
            issued_at: row.get("issued_at"),
            rotated_at: row.get("rotated_at"),
            expires_at: row.get("expires_at"),
            revoked_at: row.get("revoked_at"),
            revoke_reason: row.get("revoke_reason"),
        })
        .collect())
}

pub async fn revoke_principal_refresh_sessions(
    pool: &PgPool,
    principal_id: &str,
    reason: Option<&str>,
) -> Result<u64> {
    let result = sqlx::query(
        r#"
        UPDATE refresh_sessions
        SET revoked_at = COALESCE(revoked_at, NOW()),
            revoke_reason = COALESCE(revoke_reason, $2)
        WHERE principal_id = $1 AND revoked_at IS NULL
        "#,
    )
    .bind(principal_id)
    .bind(reason)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

pub async fn revoke_client_refresh_sessions(
    pool: &PgPool,
    client_id: &str,
    reason: Option<&str>,
) -> Result<u64> {
    let result = sqlx::query(
        r#"
        UPDATE refresh_sessions
        SET revoked_at = COALESCE(revoked_at, NOW()),
            revoke_reason = COALESCE(revoke_reason, $2)
        WHERE client_id = $1 AND revoked_at IS NULL
        "#,
    )
    .bind(client_id)
    .bind(reason)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

pub async fn has_active_refresh_session_for_principal(
    pool: &PgPool,
    principal_id: &str,
) -> Result<bool> {
    let row = sqlx::query(
        r#"
        SELECT 1
        FROM refresh_sessions
        WHERE principal_id = $1
          AND revoked_at IS NULL
          AND expires_at > NOW()
        LIMIT 1
        "#,
    )
    .bind(principal_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.is_some())
}

use anyhow::Result;
use bcrypt::{hash, DEFAULT_COST};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{
    authorization_code_hash, browser_session_hash, CreateOidcClientRequest, OidcAuthorizationCode,
    OidcBrowserSession, OidcClient, UpdateOidcClientRequest,
};

/// Persist a validated OIDC relying-party registration without ever storing its secret in plaintext.
pub async fn create_oidc_client(
    pool: &PgPool,
    request: &CreateOidcClientRequest,
) -> Result<OidcClient> {
    let secret_hash = request
        .client_secret
        .as_deref()
        .map(|secret| hash(secret, DEFAULT_COST))
        .transpose()?;
    let now = chrono::Local::now().naive_utc();
    let grant_types = request
        .grant_types
        .clone()
        .unwrap_or_else(|| vec!["authorization_code".to_string()]);
    let scopes = request.scopes.clone().unwrap_or_else(|| {
        vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ]
    });
    Ok(sqlx::query_as::<_, OidcClient>(
        "INSERT INTO oidc_clients (id, client_id, client_secret_hash, name, description, client_type, redirect_uris, grant_types, scopes, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id, client_id, name, description, client_type, redirect_uris, grant_types, scopes, active, created_at, updated_at",
    ).bind(Uuid::new_v4().to_string()).bind(&request.client_id).bind(secret_hash).bind(&request.name).bind(&request.description).bind(&request.client_type).bind(&request.redirect_uris).bind(grant_types).bind(scopes).bind(now).bind(now).fetch_one(pool).await?)
}

pub async fn list_oidc_clients(pool: &PgPool) -> Result<Vec<OidcClient>> {
    Ok(sqlx::query_as::<_, OidcClient>("SELECT id, client_id, name, description, client_type, redirect_uris, grant_types, scopes, active, created_at, updated_at FROM oidc_clients ORDER BY created_at DESC").fetch_all(pool).await?)
}

pub async fn get_oidc_client(pool: &PgPool, client_id: &str) -> Result<Option<OidcClient>> {
    Ok(sqlx::query_as::<_, OidcClient>("SELECT id, client_id, name, description, client_type, redirect_uris, grant_types, scopes, active, created_at, updated_at FROM oidc_clients WHERE client_id = $1")
        .bind(client_id).fetch_optional(pool).await?)
}

/// Return only the authentication material required by the token endpoint.
pub async fn get_oidc_client_secret_hash(
    pool: &PgPool,
    client_id: &str,
) -> Result<Option<(String, Option<String>, bool)>> {
    Ok(sqlx::query_as::<_, (String, Option<String>, bool)>(
        "SELECT client_type, client_secret_hash, active FROM oidc_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn get_active_authorization_code(
    pool: &PgPool,
    raw_code: &str,
) -> Result<Option<OidcAuthorizationCode>> {
    let row = sqlx::query_as::<_, (String, String, String, Vec<String>, Option<String>, String, i64)>(
        "SELECT client_id, user_id, redirect_uri, scopes, nonce, code_challenge, extract(epoch from expires_at)::bigint FROM oidc_authorization_codes WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > NOW()",
    ).bind(authorization_code_hash(raw_code)).fetch_optional(pool).await?;
    Ok(row.map(
        |(client_id, user_id, redirect_uri, scopes, nonce, code_challenge, expires_at)| {
            OidcAuthorizationCode {
                client_id,
                user_id,
                redirect_uri,
                scopes,
                nonce,
                code_challenge,
                expires_at,
            }
        },
    ))
}

pub async fn update_oidc_client(
    pool: &PgPool,
    client_id: &str,
    request: &UpdateOidcClientRequest,
) -> Result<Option<OidcClient>> {
    let now = chrono::Local::now().naive_utc();
    Ok(sqlx::query_as::<_, OidcClient>("UPDATE oidc_clients SET name = COALESCE($2, name), description = COALESCE($3, description), redirect_uris = COALESCE($4, redirect_uris), grant_types = COALESCE($5, grant_types), scopes = COALESCE($6, scopes), active = COALESCE($7, active), updated_at = $8 WHERE client_id = $1 RETURNING id, client_id, name, description, client_type, redirect_uris, grant_types, scopes, active, created_at, updated_at")
        .bind(client_id).bind(&request.name).bind(&request.description).bind(&request.redirect_uris).bind(&request.grant_types).bind(&request.scopes).bind(request.active).bind(now).fetch_optional(pool).await?)
}

/// Store an authorization code as a hash; the raw value is only ever returned to its redirect URI.
pub async fn create_authorization_code(
    pool: &PgPool,
    raw_code: &str,
    authorization: &OidcAuthorizationCode,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO oidc_authorization_codes (id, code_hash, client_id, user_id, redirect_uri, scopes, nonce, code_challenge, code_challenge_method, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'S256',to_timestamp($9))",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(authorization_code_hash(raw_code))
    .bind(&authorization.client_id)
    .bind(&authorization.user_id)
    .bind(&authorization.redirect_uri)
    .bind(&authorization.scopes)
    .bind(&authorization.nonce)
    .bind(&authorization.code_challenge)
    .bind(authorization.expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Atomically mark a valid authorization code as consumed and return its immutable grant context.
pub async fn consume_authorization_code(
    pool: &PgPool,
    raw_code: &str,
) -> Result<Option<OidcAuthorizationCode>> {
    let row = sqlx::query_as::<_, (String, String, String, Vec<String>, Option<String>, String, i64)>(
        "UPDATE oidc_authorization_codes SET consumed_at = NOW() WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > NOW() RETURNING client_id, user_id, redirect_uri, scopes, nonce, code_challenge, extract(epoch from expires_at)::bigint",
    )
    .bind(authorization_code_hash(raw_code))
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(client_id, user_id, redirect_uri, scopes, nonce, code_challenge, expires_at)| {
            OidcAuthorizationCode {
                client_id,
                user_id,
                redirect_uri,
                scopes,
                nonce,
                code_challenge,
                expires_at,
            }
        },
    ))
}

/// Create an opaque browser session with a hash-only database representation.
pub async fn create_browser_session(
    pool: &PgPool,
    raw_session: &str,
    session: &OidcBrowserSession,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO oidc_browser_sessions (id, session_hash, user_id, expires_at) VALUES ($1,$2,$3,to_timestamp($4))",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(browser_session_hash(raw_session))
    .bind(&session.user_id)
    .bind(session.expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Resolve an active browser cookie and touch it without extending its absolute expiry.
pub async fn resolve_browser_session(
    pool: &PgPool,
    raw_session: &str,
) -> Result<Option<OidcBrowserSession>> {
    let row = sqlx::query_as::<_, (String, i64)>(
        "UPDATE oidc_browser_sessions SET last_seen_at = NOW() WHERE session_hash = $1 AND revoked_at IS NULL AND expires_at > NOW() RETURNING user_id, extract(epoch from expires_at)::bigint",
    )
    .bind(browser_session_hash(raw_session))
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(user_id, expires_at)| OidcBrowserSession {
        user_id,
        expires_at,
    }))
}

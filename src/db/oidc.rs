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

/// Update a relying-party registration and remove pending codes when its grant boundary changes.
///
/// Audit and code invalidation share the transaction with the metadata update so an old code
/// cannot survive a disabled client or a changed redirect/scope/grant policy.
pub async fn update_oidc_client(
    pool: &PgPool,
    client_id: &str,
    request: &UpdateOidcClientRequest,
    actor: Option<&str>,
) -> Result<Option<OidcClient>> {
    let now = chrono::Local::now().naive_utc();
    let mut transaction = pool.begin().await?;
    let previous = sqlx::query_as::<_, OidcClient>(
        "SELECT id, client_id, name, description, client_type, redirect_uris, grant_types, scopes, active, created_at, updated_at FROM oidc_clients WHERE client_id = $1 FOR UPDATE",
    )
    .bind(client_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(previous) = previous else {
        transaction.commit().await?;
        return Ok(None);
    };
    let client = sqlx::query_as::<_, OidcClient>("UPDATE oidc_clients SET name = COALESCE($2, name), description = COALESCE($3, description), redirect_uris = COALESCE($4, redirect_uris), grant_types = COALESCE($5, grant_types), scopes = COALESCE($6, scopes), active = COALESCE($7, active), updated_at = $8 WHERE client_id = $1 RETURNING id, client_id, name, description, client_type, redirect_uris, grant_types, scopes, active, created_at, updated_at")
        .bind(client_id).bind(&request.name).bind(&request.description).bind(&request.redirect_uris).bind(&request.grant_types).bind(&request.scopes).bind(request.active).bind(now).fetch_one(&mut *transaction).await?;
    let trust_boundary_changed = previous.active
        && (!client.active
            || previous.redirect_uris != client.redirect_uris
            || previous.grant_types != client.grant_types
            || previous.scopes != client.scopes);
    if trust_boundary_changed {
        let invalidated_authorization_codes = sqlx::query(
            "DELETE FROM oidc_authorization_codes WHERE client_id = $1 AND consumed_at IS NULL",
        )
        .bind(client_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let event_type = if client.active {
            "oidc_client.reconfigured"
        } else {
            "oidc_client.disabled"
        };
        sqlx::query(
            "INSERT INTO audit_logs (id, event_type, actor, detail) VALUES ($1, $2, $3, $4)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(event_type)
        .bind(actor)
        .bind(format!(
            "client_id={}; invalidated_authorization_codes={}",
            client_id, invalidated_authorization_codes
        ))
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(Some(client))
}

/// Rotate only confidential-client credentials; public clients never own a reusable secret.
pub async fn rotate_oidc_client_secret(
    pool: &PgPool,
    client_id: &str,
    new_secret: &str,
) -> Result<bool> {
    let secret_hash = hash(new_secret, DEFAULT_COST)?;
    let result = sqlx::query(
        "UPDATE oidc_clients SET client_secret_hash = $2, updated_at = NOW() WHERE client_id = $1 AND client_type = 'confidential' AND active = TRUE",
    )
    .bind(client_id)
    .bind(secret_hash)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
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
        "UPDATE oidc_browser_sessions AS session
         SET last_seen_at = NOW()
         FROM users
         WHERE session.session_hash = $1
           AND session.revoked_at IS NULL
           AND session.expires_at > NOW()
           AND users.id = session.user_id
           AND users.active = TRUE
         RETURNING session.user_id, extract(epoch from session.expires_at)::bigint",
    )
    .bind(browser_session_hash(raw_session))
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(user_id, expires_at)| OidcBrowserSession {
        user_id,
        expires_at,
    }))
}

/// Revoke a browser session by its opaque cookie value; callers never expose the stored hash.
pub async fn revoke_browser_session(pool: &PgPool, raw_session: &str) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE oidc_browser_sessions SET revoked_at = NOW() WHERE session_hash = $1 AND revoked_at IS NULL",
    )
    .bind(browser_session_hash(raw_session))
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

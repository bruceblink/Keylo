use anyhow::Result;
use bcrypt::{hash, DEFAULT_COST};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{CreateOidcClientRequest, OidcClient, UpdateOidcClientRequest};

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

pub async fn update_oidc_client(
    pool: &PgPool,
    client_id: &str,
    request: &UpdateOidcClientRequest,
) -> Result<Option<OidcClient>> {
    let now = chrono::Local::now().naive_utc();
    Ok(sqlx::query_as::<_, OidcClient>("UPDATE oidc_clients SET name = COALESCE($2, name), description = COALESCE($3, description), redirect_uris = COALESCE($4, redirect_uris), grant_types = COALESCE($5, grant_types), scopes = COALESCE($6, scopes), active = COALESCE($7, active), updated_at = $8 WHERE client_id = $1 RETURNING id, client_id, name, description, client_type, redirect_uris, grant_types, scopes, active, created_at, updated_at")
        .bind(client_id).bind(&request.name).bind(&request.description).bind(&request.redirect_uris).bind(&request.grant_types).bind(&request.scopes).bind(request.active).bind(now).fetch_optional(pool).await?)
}

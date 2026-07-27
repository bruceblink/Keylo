use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::json;

use crate::{
    errors::{is_unique_violation, AuthError},
    models::{
        validate_grant_types, validate_oidc_client_registration, validate_redirect_uris,
        CreateOidcClientRequest, UpdateOidcClientRequest,
    },
    state::AppState,
};

fn database(state: &AppState) -> Result<&sqlx::PgPool, AuthError> {
    state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))
}

/// Register an OIDC relying party after applying redirect URI and client-type security rules.
pub async fn create_client(
    State(state): State<AppState>,
    Json(request): Json<CreateOidcClientRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    validate_oidc_client_registration(&request).map_err(AuthError::InvalidRequest)?;
    match crate::db::create_oidc_client(database(&state)?, &request).await {
        Ok(client) => Ok(Json(json!({"success": true, "data": client}))),
        Err(error) if is_unique_violation(error.as_ref()) => Err(AuthError::Conflict(
            "OIDC client_id already exists".to_string(),
        )),
        Err(error) => Err(AuthError::DatabaseError(error.to_string())),
    }
}

pub async fn list_clients(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let clients = crate::db::list_oidc_clients(database(&state)?)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?;
    Ok(Json(json!({"success": true, "data": clients})))
}

/// Update metadata only; client type and secrets remain immutable until explicit rotation is added.
pub async fn update_client(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    Json(request): Json<UpdateOidcClientRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    if let Some(redirect_uris) = &request.redirect_uris {
        validate_redirect_uris(redirect_uris).map_err(AuthError::InvalidRequest)?;
    }
    if let Some(grant_types) = &request.grant_types {
        validate_grant_types(grant_types).map_err(AuthError::InvalidRequest)?;
    }
    let client = crate::db::update_oidc_client(database(&state)?, &client_id, &request)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?;
    client
        .map(|value| Json(json!({"success": true, "data": value})))
        .ok_or(AuthError::NotFound)
}

pub async fn unavailable_discovery() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(
            json!({"error": "oidc_not_enabled", "message": "OIDC discovery will be enabled with the authorization endpoint"}),
        ),
    )
}

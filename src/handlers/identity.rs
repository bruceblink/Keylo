use crate::db::identity as identity_db;
use crate::errors::{is_unique_violation, AuthError};
use crate::models::{CreateIdentitySourceRequest, IdentitySource, UpdateIdentitySourceRequest};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};

const SUPPORTED_SOURCE_TYPES: [&str; 4] = ["local_password", "oauth2", "oidc_upstream", "ldap"];

fn require_db(state: &AppState) -> Result<&sqlx::PgPool, AuthError> {
    state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))
}

fn normalized_required(field_name: &str, value: &str) -> Result<String, AuthError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AuthError::InvalidRequest(format!(
            "{} must not be empty",
            field_name
        )));
    }
    if trimmed.split_whitespace().count() != 1 {
        return Err(AuthError::InvalidRequest(format!(
            "{} must not contain whitespace",
            field_name
        )));
    }
    Ok(trimmed.to_lowercase())
}

fn normalize_display_name(value: &str) -> Result<String, AuthError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AuthError::InvalidRequest(
            "display_name must not be empty".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

fn normalize_source_type(value: &str) -> Result<String, AuthError> {
    let source_type = normalized_required("source_type", value)?;
    if !SUPPORTED_SOURCE_TYPES.contains(&source_type.as_str()) {
        return Err(AuthError::InvalidRequest(format!(
            "source_type must be one of: {}",
            SUPPORTED_SOURCE_TYPES.join(", ")
        )));
    }
    Ok(source_type)
}

fn json_object_or_default(field_name: &str, value: Option<Value>) -> Result<Value, AuthError> {
    let value = value.unwrap_or_else(|| json!({}));
    if !value.is_object() {
        return Err(AuthError::InvalidRequest(format!(
            "{} must be a JSON object",
            field_name
        )));
    }
    Ok(value)
}

fn optional_json_object(
    field_name: &str,
    value: Option<Value>,
) -> Result<Option<Value>, AuthError> {
    match value {
        Some(value) if value.is_object() => Ok(Some(value)),
        Some(_) => Err(AuthError::InvalidRequest(format!(
            "{} must be a JSON object",
            field_name
        ))),
        None => Ok(None),
    }
}

pub async fn list_identity_sources(
    State(state): State<AppState>,
) -> Result<Json<Value>, AuthError> {
    let db = require_db(&state)?;
    let sources = identity_db::list_identity_sources(db)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({ "identity_sources": sources })))
}

pub async fn create_identity_source(
    State(state): State<AppState>,
    Json(payload): Json<CreateIdentitySourceRequest>,
) -> Result<Json<IdentitySource>, AuthError> {
    let name = normalized_required("name", &payload.name)?;
    let source_type = normalize_source_type(&payload.source_type)?;
    let display_name = normalize_display_name(&payload.display_name)?;
    let config = json_object_or_default("config", payload.config)?;
    let claim_mapping = json_object_or_default("claim_mapping", payload.claim_mapping)?;
    let description = payload
        .description
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    let db = require_db(&state)?;
    let source = identity_db::create_identity_source(
        db,
        identity_db::CreateIdentitySourceParams {
            name: &name,
            source_type: &source_type,
            display_name: &display_name,
            description: description.as_deref(),
            config: &config,
            claim_mapping: &claim_mapping,
            jit_enabled: payload.jit_enabled.unwrap_or(false),
            auto_link_enabled: payload.auto_link_enabled.unwrap_or(true),
            active: payload.active.unwrap_or(true),
        },
    )
    .await
    .map_err(|e| {
        if is_unique_violation(e.as_ref()) {
            AuthError::Conflict(format!(
                "Identity source '{}' already exists; choose a different name or update it.",
                name
            ))
        } else {
            AuthError::DatabaseError(e.to_string())
        }
    })?;

    Ok(Json(source))
}

pub async fn get_identity_source(
    State(state): State<AppState>,
    Path(source_id): Path<String>,
) -> Result<Json<IdentitySource>, AuthError> {
    let db = require_db(&state)?;
    let source = identity_db::get_identity_source(db, &source_id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        .ok_or(AuthError::NotFound)?;

    Ok(Json(source))
}

pub async fn update_identity_source(
    State(state): State<AppState>,
    Path(source_id): Path<String>,
    Json(payload): Json<UpdateIdentitySourceRequest>,
) -> Result<Json<IdentitySource>, AuthError> {
    let display_name = payload
        .display_name
        .as_deref()
        .map(normalize_display_name)
        .transpose()?;
    let description = payload
        .description
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let config = optional_json_object("config", payload.config)?;
    let claim_mapping = optional_json_object("claim_mapping", payload.claim_mapping)?;

    let db = require_db(&state)?;
    let source = identity_db::update_identity_source(
        db,
        identity_db::UpdateIdentitySourceParams {
            id: &source_id,
            display_name: display_name.as_deref(),
            description: description.as_deref(),
            config: config.as_ref(),
            claim_mapping: claim_mapping.as_ref(),
            jit_enabled: payload.jit_enabled,
            auto_link_enabled: payload.auto_link_enabled,
            active: payload.active,
        },
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?
    .ok_or(AuthError::NotFound)?;

    Ok(Json(source))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_source_type_accepts_supported_values() {
        assert_eq!(normalize_source_type(" OAUTH2 ").unwrap(), "oauth2");
    }

    #[test]
    fn normalize_source_type_rejects_unsupported_values() {
        let err = normalize_source_type("saml").unwrap_err();

        assert!(matches!(err, AuthError::InvalidRequest(_)));
    }

    #[test]
    fn json_object_or_default_rejects_non_objects() {
        let err = json_object_or_default("config", Some(json!([]))).unwrap_err();

        assert!(matches!(err, AuthError::InvalidRequest(_)));
    }
}

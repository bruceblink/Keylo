use crate::db::identity as identity_db;
use crate::errors::{is_unique_violation, AuthError};
use crate::models::{
    oidc_discovery_url, parse_oidc_upstream_config, parse_oidc_upstream_discovery,
    CreateIdentitySourceRequest, IdentitySource, OidcUpstreamDiscovery,
    UpdateIdentitySourceRequest,
};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::response::Redirect;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

const SUPPORTED_SOURCE_TYPES: [&str; 4] = ["local_password", "oauth2", "oidc_upstream", "ldap"];

#[derive(Deserialize)]
pub struct OidcUpstreamCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

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

fn validate_identity_source_config(source_type: &str, config: &Value) -> Result<(), AuthError> {
    if source_type == "oidc_upstream" {
        parse_oidc_upstream_config(config).map_err(AuthError::InvalidRequest)?;
    }
    Ok(())
}

pub async fn list_identity_sources(
    State(state): State<AppState>,
) -> Result<Json<Value>, AuthError> {
    let db = require_db(&state)?;
    let sources = identity_db::list_identity_sources(db)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "identity_sources": sources
            .into_iter()
            .map(IdentitySource::redacted_for_response)
            .collect::<Vec<_>>()
    })))
}

pub async fn create_identity_source(
    State(state): State<AppState>,
    Json(payload): Json<CreateIdentitySourceRequest>,
) -> Result<Json<IdentitySource>, AuthError> {
    let name = normalized_required("name", &payload.name)?;
    let source_type = normalize_source_type(&payload.source_type)?;
    let display_name = normalize_display_name(&payload.display_name)?;
    let config = json_object_or_default("config", payload.config)?;
    validate_identity_source_config(&source_type, &config)?;
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

    Ok(Json(source.redacted_for_response()))
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

    Ok(Json(source.redacted_for_response()))
}

/// Fetch and validate public OIDC Discovery metadata for an active upstream source.
pub async fn discover_oidc_upstream(
    State(state): State<AppState>,
    Path(source_id): Path<String>,
) -> Result<Json<OidcUpstreamDiscovery>, AuthError> {
    let db = require_db(&state)?;
    let source = identity_db::get_identity_source(db, &source_id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        .ok_or(AuthError::NotFound)?;
    if !source.active || source.source_type != "oidc_upstream" {
        return Err(AuthError::InvalidRequest(
            "An active oidc_upstream identity source is required".to_string(),
        ));
    }
    let config = parse_oidc_upstream_config(&source.config).map_err(AuthError::InvalidRequest)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| AuthError::DatabaseError("Failed to create OIDC HTTP client".to_string()))?;
    let response = client
        .get(oidc_discovery_url(&config.issuer))
        .send()
        .await
        .map_err(|_| {
            AuthError::InvalidRequest("Unable to fetch OIDC Discovery document".to_string())
        })?;
    if !response.status().is_success() {
        return Err(AuthError::InvalidRequest(
            "OIDC Discovery endpoint returned an unsuccessful status".to_string(),
        ));
    }
    let document = response.json::<Value>().await.map_err(|_| {
        AuthError::InvalidRequest("OIDC Discovery document is not valid JSON".to_string())
    })?;
    let discovery = parse_oidc_upstream_discovery(&config.issuer, &document)
        .map_err(AuthError::InvalidRequest)?;
    Ok(Json(discovery))
}

/// Begin a secure upstream authorization-code flow and redirect the browser to the IdP.
pub async fn begin_oidc_upstream_login(
    State(state): State<AppState>,
    Path(source_name): Path<String>,
) -> Result<Redirect, AuthError> {
    let db = require_db(&state)?;
    let source = identity_db::get_active_identity_source_by_name(db, &source_name)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        .filter(|source| source.source_type == "oidc_upstream")
        .ok_or(AuthError::NotFound)?;
    let config = parse_oidc_upstream_config(&source.config).map_err(AuthError::InvalidRequest)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| AuthError::DatabaseError("Failed to create OIDC HTTP client".to_string()))?;
    let document = client
        .get(oidc_discovery_url(&config.issuer))
        .send()
        .await
        .map_err(|_| {
            AuthError::InvalidRequest("Unable to fetch OIDC Discovery document".to_string())
        })?
        .error_for_status()
        .map_err(|_| {
            AuthError::InvalidRequest(
                "OIDC Discovery endpoint returned an unsuccessful status".to_string(),
            )
        })?
        .json::<Value>()
        .await
        .map_err(|_| {
            AuthError::InvalidRequest("OIDC Discovery document is not valid JSON".to_string())
        })?;
    let discovery = parse_oidc_upstream_discovery(&config.issuer, &document)
        .map_err(AuthError::InvalidRequest)?;
    let transaction = crate::models::new_oidc_upstream_authorization_state();
    let mfa_key = state.config.mfa_secret_key_bytes().map_err(|_| {
        AuthError::DatabaseError("MFA_SECRET_KEY is required for upstream OIDC login".to_string())
    })?;
    let encrypted_code_verifier =
        crate::models::encrypt_totp_seed(&transaction.code_verifier, &mfa_key).map_err(|_| {
            AuthError::DatabaseError("Failed to protect upstream PKCE verifier".to_string())
        })?;
    crate::db::create_oidc_upstream_authorization(
        db,
        &source.id,
        &transaction,
        &encrypted_code_verifier,
        chrono::Utc::now().timestamp() + 300,
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    let scope = config.scopes.join(" ");
    let url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        discovery.authorization_endpoint,
        urlencoding::encode(&config.client_id),
        urlencoding::encode(&config.redirect_uri),
        urlencoding::encode(&scope),
        urlencoding::encode(&transaction.state),
        urlencoding::encode(&transaction.nonce),
        urlencoding::encode(&transaction.code_challenge),
    );
    Ok(Redirect::temporary(&url))
}

/// Consume an upstream callback, exchange its code, and return only a verified external subject.
pub async fn complete_oidc_upstream_login(
    State(state): State<AppState>,
    Query(query): Query<OidcUpstreamCallbackQuery>,
) -> Result<Json<Value>, AuthError> {
    if query.error.is_some() {
        return Err(AuthError::InvalidRequest(
            "Upstream OIDC authorization was denied".to_string(),
        ));
    }
    let db = require_db(&state)?;
    let state_value = query
        .state
        .as_deref()
        .ok_or_else(|| AuthError::InvalidRequest("Missing OIDC callback state".to_string()))?;
    let code = query
        .code
        .as_deref()
        .ok_or_else(|| AuthError::InvalidRequest("Missing OIDC authorization code".to_string()))?;
    let transaction = crate::db::consume_oidc_upstream_authorization(db, state_value)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        .ok_or_else(|| {
            AuthError::InvalidRequest("Invalid or expired OIDC callback state".to_string())
        })?;
    let source = identity_db::get_identity_source(db, &transaction.source_id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        .filter(|source| source.active && source.source_type == "oidc_upstream")
        .ok_or(AuthError::NotFound)?;
    let config = parse_oidc_upstream_config(&source.config).map_err(AuthError::InvalidRequest)?;
    let key = state.config.mfa_secret_key_bytes().map_err(|_| {
        AuthError::DatabaseError("MFA_SECRET_KEY is required for upstream OIDC login".to_string())
    })?;
    let verifier = crate::models::decrypt_totp_seed(&transaction.code_verifier_encrypted, &key)
        .map_err(|_| {
            AuthError::InvalidRequest(
                "OIDC authorization transaction cannot be decrypted".to_string(),
            )
        })?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| AuthError::DatabaseError("Failed to create OIDC HTTP client".to_string()))?;
    let discovery_document = client
        .get(oidc_discovery_url(&config.issuer))
        .send()
        .await
        .map_err(|_| {
            AuthError::InvalidRequest("Unable to fetch OIDC Discovery document".to_string())
        })?
        .error_for_status()
        .map_err(|_| {
            AuthError::InvalidRequest(
                "OIDC Discovery endpoint returned an unsuccessful status".to_string(),
            )
        })?
        .json::<Value>()
        .await
        .map_err(|_| {
            AuthError::InvalidRequest("OIDC Discovery document is not valid JSON".to_string())
        })?;
    let discovery = parse_oidc_upstream_discovery(&config.issuer, &discovery_document)
        .map_err(AuthError::InvalidRequest)?;
    let token = client
        .post(&discovery.token_endpoint)
        .basic_auth(&config.client_id, Some(&config.client_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &config.redirect_uri),
            ("code_verifier", &verifier),
        ])
        .send()
        .await
        .map_err(|_| {
            AuthError::InvalidRequest("Unable to exchange OIDC authorization code".to_string())
        })?
        .error_for_status()
        .map_err(|_| {
            AuthError::InvalidRequest("OIDC token endpoint rejected authorization code".to_string())
        })?
        .json::<Value>()
        .await
        .map_err(|_| AuthError::InvalidRequest("OIDC token response is invalid".to_string()))?;
    let id_token = token
        .get("id_token")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AuthError::InvalidRequest("OIDC token response is missing id_token".to_string())
        })?;
    let jwks = client
        .get(&discovery.jwks_uri)
        .send()
        .await
        .map_err(|_| AuthError::InvalidRequest("Unable to fetch OIDC JWKS".to_string()))?
        .error_for_status()
        .map_err(|_| {
            AuthError::InvalidRequest(
                "OIDC JWKS endpoint returned an unsuccessful status".to_string(),
            )
        })?
        .json::<crate::models::OidcUpstreamJwks>()
        .await
        .map_err(|_| AuthError::InvalidRequest("OIDC JWKS is invalid".to_string()))?;
    let claims = crate::models::verify_oidc_upstream_id_token(id_token, &jwks)
        .map_err(AuthError::InvalidRequest)?;
    crate::models::validate_oidc_upstream_id_token_claims(
        &claims,
        &config.issuer,
        &config.client_id,
        &transaction.nonce_hash,
        chrono::Utc::now().timestamp(),
    )
    .map_err(AuthError::InvalidRequest)?;
    Ok(Json(
        json!({"subject": claims.sub, "email": claims.email, "username": claims.preferred_username}),
    ))
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
    if let Some(config) = config.as_ref() {
        let existing = identity_db::get_identity_source(db, &source_id)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?
            .ok_or(AuthError::NotFound)?;
        validate_identity_source_config(&existing.source_type, config)?;
    }
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

    Ok(Json(source.redacted_for_response()))
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

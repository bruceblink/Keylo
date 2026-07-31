use crate::db::identity as identity_db;
use crate::errors::{is_unique_violation, AuthError};
use crate::models::{
    oidc_discovery_url, parse_oidc_upstream_config, parse_oidc_upstream_discovery, Claims,
    CreateIdentitySourceRequest, IdentitySource, OidcUpstreamDiscovery, OidcUpstreamProfile,
    UpdateIdentitySourceRequest,
};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::response::Redirect;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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

/// Preserve stored credential fields when an update sends the API redaction placeholder back.
fn preserve_redacted_identity_secrets(existing: &Value, incoming: &mut Value) {
    let (Some(existing_object), Some(incoming_object)) =
        (existing.as_object(), incoming.as_object_mut())
    else {
        return;
    };
    for (key, existing_value) in existing_object {
        let normalized = key.to_ascii_lowercase();
        if normalized.contains("secret") || normalized.contains("password") || normalized == "token"
        {
            let should_preserve = incoming_object
                .get(key)
                .and_then(Value::as_str)
                .is_none_or(|value| value == "[REDACTED]");
            if should_preserve {
                incoming_object.insert(key.clone(), existing_value.clone());
            }
        } else if let Some(incoming_child) = incoming_object.get_mut(key) {
            preserve_redacted_identity_secrets(existing_value, incoming_child);
        }
    }
}

fn validate_identity_source_config(source_type: &str, config: &Value) -> Result<(), AuthError> {
    if source_type == "oidc_upstream" {
        parse_oidc_upstream_config(config).map_err(AuthError::InvalidRequest)?;
    }
    Ok(())
}

/// Validate claim mappings when the source is an executable upstream OIDC login.
fn validate_identity_source_claim_mapping(
    source_type: &str,
    claim_mapping: &Value,
) -> Result<(), AuthError> {
    if source_type == "oidc_upstream" {
        crate::models::parse_oidc_upstream_claim_mapping(claim_mapping)
            .map_err(AuthError::InvalidRequest)?;
    }
    Ok(())
}

/// Build the stable external-provider key used to keep one source's subjects separate from another.
fn oidc_mapping_provider(source: &IdentitySource) -> String {
    format!("oidc_upstream:{}", source.id)
}

/// Generate a deterministic fallback username when an upstream preferred username is already used.
fn oidc_jit_username(source: &IdentitySource, profile: &OidcUpstreamProfile) -> String {
    let digest = Sha256::digest(format!("{}:{}", source.id, profile.external_subject).as_bytes());
    format!("{}-{}", profile.username, hex::encode(&digest[..4]))
}

/// Bind an OIDC subject once; a concurrent binding to another user is a conflict, never a reassignment.
async fn create_oidc_user_mapping(
    db: &sqlx::PgPool,
    source: &IdentitySource,
    profile: &OidcUpstreamProfile,
    user_id: &str,
) -> Result<(), AuthError> {
    let provider = oidc_mapping_provider(source);
    match crate::db::create_external_user_mapping(
        db,
        &provider,
        &profile.external_subject,
        user_id,
        Some(&json!({"source_name": source.name, "email": profile.email})),
    )
    .await
    {
        Ok(()) => {
            crate::db::create_audit_log(
                db,
                "identity_source.account.linked",
                Some(user_id),
                Some(&format!("user_id={}; source_id={}", user_id, source.id)),
            )
            .await
            .map_err(|_| {
                AuthError::DatabaseError("Failed to audit OIDC identity link".to_string())
            })?;
            Ok(())
        }
        Err(error) if is_unique_violation(error.as_ref()) => {
            let existing_user_id =
                crate::db::get_mapped_user_id(db, &provider, &profile.external_subject)
                    .await
                    .map_err(|_| {
                        AuthError::DatabaseError(
                            "Failed to resolve OIDC mapping conflict".to_string(),
                        )
                    })?;
            if existing_user_id.as_deref() == Some(user_id) {
                Ok(())
            } else {
                Err(AuthError::Conflict(
                    "Upstream OIDC identity is already linked to another Keylo user".to_string(),
                ))
            }
        }
        Err(_) => Err(AuthError::DatabaseError(
            "Failed to create OIDC user mapping".to_string(),
        )),
    }
}

/// Keep the local email immutable while retaining the latest upstream email for review and audit.
async fn record_oidc_email_change(
    db: &sqlx::PgPool,
    source: &IdentitySource,
    profile: &OidcUpstreamProfile,
    mapping: &crate::db::ExternalUserMapping,
) -> Result<(), AuthError> {
    let observed_email = mapping
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("email"))
        .and_then(Value::as_str);
    if observed_email == Some(profile.email.as_str()) {
        return Ok(());
    }
    let mut metadata = mapping.metadata.clone().unwrap_or_else(|| json!({}));
    let object = metadata.as_object_mut().ok_or_else(|| {
        AuthError::DatabaseError("OIDC identity mapping metadata is invalid".to_string())
    })?;
    object.insert("source_name".to_string(), json!(source.name));
    object.insert("email".to_string(), json!(profile.email));
    object.insert("email_verified".to_string(), json!(profile.email_verified));
    let provider = oidc_mapping_provider(source);
    if crate::db::update_external_user_mapping_email(
        db,
        &provider,
        &profile.external_subject,
        &mapping.user_id,
        &metadata,
    )
    .await
    .map_err(|_| AuthError::DatabaseError("Failed to record external email change".to_string()))?
    {
        crate::db::create_audit_log(
            db,
            "identity_source.email_change_observed",
            Some(&mapping.user_id),
            Some(&format!(
                "user_id={}; source_id={}",
                mapping.user_id, source.id
            )),
        )
        .await
        .map_err(|_| {
            AuthError::DatabaseError("Failed to audit external email change".to_string())
        })?;
    }
    Ok(())
}

/// Resolve a verified OIDC identity to an active Keylo user, creating a mapping only under source policy.
async fn resolve_oidc_upstream_user(
    db: &sqlx::PgPool,
    source: &IdentitySource,
    profile: &OidcUpstreamProfile,
) -> Result<crate::models::User, AuthError> {
    let provider = oidc_mapping_provider(source);
    if let Some(mapping) =
        crate::db::get_external_user_mapping(db, &provider, &profile.external_subject)
            .await
            .map_err(|_| {
                AuthError::DatabaseError("Failed to resolve OIDC user mapping".to_string())
            })?
    {
        let user = crate::db::get_user_by_id(db, &mapping.user_id)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to load mapped user".to_string()))?
            .filter(|user| user.active)
            .ok_or(AuthError::Forbidden)?;
        record_oidc_email_change(db, source, profile, &mapping).await?;
        return Ok(user);
    }

    if let Some(user) = crate::db::get_user_by_email(db, &profile.email)
        .await
        .map_err(|_| AuthError::DatabaseError("Failed to look up OIDC email".to_string()))?
    {
        if !source.auto_link_enabled || !profile.email_verified {
            return Err(AuthError::Conflict(
                "An existing Keylo account requires an explicit identity link".to_string(),
            ));
        }
        if !user.active {
            return Err(AuthError::Forbidden);
        }
        create_oidc_user_mapping(db, source, profile, &user.id).await?;
        return Ok(user);
    }

    if !source.jit_enabled {
        return Err(AuthError::Forbidden);
    }

    let username = match crate::db::get_user_by_username(db, &profile.username)
        .await
        .map_err(|_| AuthError::DatabaseError("Failed to look up OIDC username".to_string()))?
    {
        Some(_) => oidc_jit_username(source, profile),
        None => profile.username.clone(),
    };
    let user = crate::db::create_user(db, &username, &profile.email, None)
        .await
        .map_err(|error| {
            if is_unique_violation(error.as_ref()) {
                AuthError::Conflict(
                    "OIDC account conflicts with an existing Keylo user".to_string(),
                )
            } else {
                AuthError::DatabaseError("Failed to create JIT OIDC user".to_string())
            }
        })?;
    if let Err(error) = create_oidc_user_mapping(db, source, profile, &user.id).await {
        crate::db::delete_user(db, &user.id).await.map_err(|_| {
            AuthError::DatabaseError("Failed to clean up conflicting JIT OIDC user".to_string())
        })?;
        return Err(error);
    }
    Ok(user)
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
    validate_identity_source_claim_mapping(&source_type, &claim_mapping)?;
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

/// List safely redacted local users associated with one upstream OIDC identity source.
pub async fn list_oidc_identity_source_links(
    State(state): State<AppState>,
    Path(source_id): Path<String>,
) -> Result<Json<Value>, AuthError> {
    let db = require_db(&state)?;
    let source = identity_db::get_identity_source(db, &source_id)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?
        .filter(|source| source.source_type == "oidc_upstream")
        .ok_or(AuthError::NotFound)?;
    let links = identity_db::list_oidc_identity_source_links(db, &source.id)
        .await
        .map_err(|_| {
            AuthError::DatabaseError("Failed to list identity source links".to_string())
        })?;
    Ok(Json(json!({"source_id": source.id, "links": links})))
}

/// Let an administrator remove one upstream link while preserving the last-login-method guard.
pub async fn unlink_oidc_identity_source_link(
    claims: Claims,
    State(state): State<AppState>,
    Path((source_id, user_id)): Path<(String, String)>,
) -> Result<Json<Value>, AuthError> {
    let db = require_db(&state)?;
    let source = identity_db::get_identity_source(db, &source_id)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?
        .filter(|source| source.source_type == "oidc_upstream")
        .ok_or(AuthError::NotFound)?;
    let provider = oidc_mapping_provider(&source);
    match crate::db::unlink_external_user_mapping(db, &provider, &user_id)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?
    {
        crate::db::ExternalUserMappingUnlinkResult::NotFound => Err(AuthError::NotFound),
        crate::db::ExternalUserMappingUnlinkResult::LastLoginMethod => Err(AuthError::Conflict(
            "Cannot unlink the last available login method".to_string(),
        )),
        crate::db::ExternalUserMappingUnlinkResult::Unlinked => {
            if let Some(principal) = crate::db::ensure_user_principal(db, &user_id)
                .await
                .map_err(|_| {
                    AuthError::DatabaseError("Failed to resolve user principal".to_string())
                })?
            {
                crate::db::revoke_principal_client_refresh_sessions(
                    db,
                    &principal.id,
                    &provider,
                    Some("admin_upstream_identity_unlinked"),
                )
                .await
                .map_err(|_| {
                    AuthError::DatabaseError("Failed to revoke upstream sessions".to_string())
                })?;
            }
            crate::db::create_audit_log(
                db,
                "identity_source.account.admin_unlinked",
                Some(&claims.sub),
                Some(&format!("user_id={}; source_id={}", user_id, source.id)),
            )
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to audit identity unlink".to_string()))?;
            Ok(Json(
                json!({"success": true, "source_id": source.id, "user_id": user_id}),
            ))
        }
    }
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

/// Consume an upstream callback, verify its identity, and resolve it to a Keylo user.
pub async fn complete_oidc_upstream_login(
    State(state): State<AppState>,
    Query(query): Query<OidcUpstreamCallbackQuery>,
) -> Result<Json<Value>, AuthError> {
    let db = require_db(&state)?;
    let state_value = query
        .state
        .as_deref()
        .ok_or_else(|| AuthError::InvalidRequest("Missing OIDC callback state".to_string()))?;
    if query.error.is_some() {
        // An IdP error ends this browser transaction too, so its state cannot be reused with a later code.
        crate::db::consume_oidc_upstream_authorization(db, state_value)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?
            .ok_or_else(|| {
                AuthError::InvalidRequest("Invalid or expired OIDC callback state".to_string())
            })?;
        return Err(AuthError::InvalidRequest(
            "Upstream OIDC authorization was denied".to_string(),
        ));
    }
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
    let claims = if let Some(userinfo_endpoint) = discovery.userinfo_endpoint.as_deref() {
        let access_token = token
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                AuthError::InvalidRequest(
                    "OIDC token response is missing access_token for UserInfo".to_string(),
                )
            })?;
        let userinfo = client
            .get(userinfo_endpoint)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|_| AuthError::InvalidRequest("Unable to fetch OIDC UserInfo".to_string()))?
            .error_for_status()
            .map_err(|_| {
                AuthError::InvalidRequest(
                    "OIDC UserInfo endpoint rejected access token".to_string(),
                )
            })?
            .json::<Value>()
            .await
            .map_err(|_| {
                AuthError::InvalidRequest("OIDC UserInfo response is invalid".to_string())
            })?;
        crate::models::merge_oidc_upstream_userinfo(claims, &userinfo)
            .map_err(AuthError::InvalidRequest)?
    } else {
        claims
    };
    let profile = crate::models::oidc_upstream_profile_with_mapping(&claims, &source.claim_mapping)
        .map_err(AuthError::InvalidRequest)?;
    let user = resolve_oidc_upstream_user(db, &source, &profile).await?;
    let tokens = crate::handlers::issue_external_user_session(
        &state,
        db,
        &user,
        &oidc_mapping_provider(&source),
    )
    .await?;
    serde_json::to_value(tokens).map(Json).map_err(|_| {
        AuthError::InternalServerError("Failed to serialize OIDC login response".to_string())
    })
}

pub async fn update_identity_source(
    claims: Claims,
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
    let mut config = optional_json_object("config", payload.config)?;
    let claim_mapping = optional_json_object("claim_mapping", payload.claim_mapping)?;

    let db = require_db(&state)?;
    let needs_existing =
        config.is_some() || claim_mapping.is_some() || payload.active == Some(false);
    let existing = if needs_existing {
        Some(
            identity_db::get_identity_source(db, &source_id)
                .await
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?
                .ok_or(AuthError::NotFound)?,
        )
    } else {
        None
    };
    if let Some(config) = config.as_mut() {
        let existing = existing
            .as_ref()
            .expect("existing source required for config validation");
        preserve_redacted_identity_secrets(&existing.config, config);
        validate_identity_source_config(&existing.source_type, config)?;
    }
    if let Some(claim_mapping) = claim_mapping.as_ref() {
        let existing = existing
            .as_ref()
            .expect("existing source required for claim mapping validation");
        validate_identity_source_claim_mapping(&existing.source_type, claim_mapping)?;
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

    let upstream_source_disabled = existing.as_ref().is_some_and(|previous| {
        previous.active && !source.active && previous.source_type == "oidc_upstream"
    });
    let upstream_source_reconfigured = existing.as_ref().is_some_and(|previous| {
        previous.active
            && source.active
            && previous.source_type == "oidc_upstream"
            && previous.config != source.config
    });
    if upstream_source_disabled || upstream_source_reconfigured {
        let (revoke_reason, audit_event) = if upstream_source_disabled {
            ("identity_source_disabled", "identity_source.disabled")
        } else {
            (
                "identity_source_reconfigured",
                "identity_source.reconfigured",
            )
        };
        let revoked_sessions = crate::db::revoke_client_refresh_sessions(
            db,
            &oidc_mapping_provider(&source),
            Some(revoke_reason),
        )
        .await
        .map_err(|_| AuthError::DatabaseError("Failed to revoke upstream sessions".to_string()))?;
        let invalidated_authorizations =
            crate::db::invalidate_oidc_upstream_authorizations(db, &source.id)
                .await
                .map_err(|_| {
                    AuthError::DatabaseError(
                        "Failed to invalidate upstream authorizations".to_string(),
                    )
                })?;
        crate::db::create_audit_log(
            db,
            audit_event,
            Some(&claims.sub),
            Some(&format!(
                "source_id={}; revoked_sessions={}; invalidated_authorizations={}",
                source.id, revoked_sessions, invalidated_authorizations
            )),
        )
        .await
        .map_err(|_| {
            AuthError::DatabaseError("Failed to audit identity source disable".to_string())
        })?;
    }

    Ok(Json(source.redacted_for_response()))
}

/// Unlink the caller's OIDC source and revoke only sessions issued through that source.
pub async fn unlink_oidc_upstream_identity(
    claims: Claims,
    State(state): State<AppState>,
    Path(source_id): Path<String>,
) -> Result<Json<Value>, AuthError> {
    if matches!(claims.principal_type.as_deref(), Some(kind) if kind != "user") {
        return Err(AuthError::Unauthorized);
    }
    let user_id = claims.uid.as_deref().ok_or(AuthError::Unauthorized)?;
    let db = require_db(&state)?;
    let source = identity_db::get_identity_source(db, &source_id)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?
        .filter(|source| source.source_type == "oidc_upstream")
        .ok_or(AuthError::NotFound)?;
    let provider = oidc_mapping_provider(&source);
    match crate::db::unlink_external_user_mapping(db, &provider, user_id)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?
    {
        crate::db::ExternalUserMappingUnlinkResult::NotFound => Err(AuthError::NotFound),
        crate::db::ExternalUserMappingUnlinkResult::LastLoginMethod => Err(AuthError::Conflict(
            "Cannot unlink the last available login method".to_string(),
        )),
        crate::db::ExternalUserMappingUnlinkResult::Unlinked => {
            if let Some(principal) = crate::db::ensure_user_principal(db, user_id)
                .await
                .map_err(|_| {
                    AuthError::DatabaseError("Failed to resolve user principal".to_string())
                })?
            {
                crate::db::revoke_principal_client_refresh_sessions(
                    db,
                    &principal.id,
                    &provider,
                    Some("upstream_identity_unlinked"),
                )
                .await
                .map_err(|_| {
                    AuthError::DatabaseError("Failed to revoke upstream sessions".to_string())
                })?;
            }
            crate::db::create_audit_log(
                db,
                "identity_source.account.unlinked",
                Some(&claims.sub),
                Some(&format!("user_id={}; source_id={}", user_id, source.id)),
            )
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to audit identity unlink".to_string()))?;
            Ok(Json(json!({"success": true, "source_id": source.id})))
        }
    }
}

/// Return the caller's linked upstream OIDC sources so they can make a safe unlink decision.
pub async fn list_my_oidc_upstream_identities(
    claims: Claims,
    State(state): State<AppState>,
) -> Result<Json<Value>, AuthError> {
    if matches!(claims.principal_type.as_deref(), Some(kind) if kind != "user") {
        return Err(AuthError::Unauthorized);
    }
    let user_id = claims.uid.as_deref().ok_or(AuthError::Unauthorized)?;
    let db = require_db(&state)?;
    let identity_sources = identity_db::list_linked_oidc_identity_sources(db, user_id)
        .await
        .map_err(|_| {
            AuthError::DatabaseError("Failed to list linked identity sources".to_string())
        })?;
    Ok(Json(json!({"identity_sources": identity_sources})))
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

    #[test]
    fn redacted_identity_secrets_are_preserved_during_update() {
        let existing = json!({
            "client_secret": "original-secret",
            "nested": {"bind_password": "original-password"},
            "issuer": "https://idp.example"
        });
        let mut incoming = json!({
            "client_secret": "[REDACTED]",
            "nested": {"bind_password": "[REDACTED]"},
            "issuer": "https://new-idp.example"
        });

        preserve_redacted_identity_secrets(&existing, &mut incoming);

        assert_eq!(incoming["client_secret"], "original-secret");
        assert_eq!(incoming["nested"]["bind_password"], "original-password");
        assert_eq!(incoming["issuer"], "https://new-idp.example");
    }

    #[test]
    fn jit_username_is_stable_and_disambiguates_the_profile_username() {
        let source = IdentitySource {
            id: "88c474cd-d20b-48fb-8b39-1b30d177e10d".to_string(),
            name: "corporate-idp".to_string(),
            source_type: "oidc_upstream".to_string(),
            display_name: "Corporate IdP".to_string(),
            description: None,
            config: json!({}),
            claim_mapping: json!({}),
            jit_enabled: true,
            auto_link_enabled: true,
            active: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let profile = OidcUpstreamProfile {
            external_subject: "employee-123".to_string(),
            username: "alice".to_string(),
            email: "alice@example.com".to_string(),
            email_verified: true,
        };

        let first = oidc_jit_username(&source, &profile);

        assert_eq!(first, oidc_jit_username(&source, &profile));
        assert!(first.starts_with("alice-"));
        assert_eq!(
            oidc_mapping_provider(&source),
            "oidc_upstream:88c474cd-d20b-48fb-8b39-1b30d177e10d"
        );
    }
}

use crate::db::identity as identity_db;
use crate::errors::{is_unique_violation, AuthError};
use crate::models::{
    oidc_discovery_url, parse_oidc_upstream_config, parse_oidc_upstream_discovery, Claims,
    CreateIdentitySourceRequest, IdentitySource, OidcUpstreamDiscovery, OidcUpstreamProfile,
    UpdateIdentitySourceRequest, IDENTITY_SOURCE_ORGANIZATION_STRATEGY_FIXED,
    IDENTITY_SOURCE_ORGANIZATION_STRATEGY_NONE, IDENTITY_SOURCE_USER_CLASS_EXTERNAL_CUSTOMER,
};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::response::Redirect;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;

const SUPPORTED_SOURCE_TYPES: [&str; 4] = ["local_password", "oauth2", "oidc_upstream", "ldap"];
const OIDC_UPSTREAM_HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const OIDC_UPSTREAM_METADATA_CACHE_TTL_SECONDS: i64 = 300;

#[derive(Deserialize)]
pub struct OidcUpstreamCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// Build one bounded HTTP client for upstream metadata and token requests.
fn oidc_upstream_http_client() -> Result<reqwest::Client, AuthError> {
    reqwest::Client::builder()
        .timeout(OIDC_UPSTREAM_HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| AuthError::DatabaseError("Failed to create OIDC HTTP client".to_string()))
}

/// Treat source updated_at as the trust configuration version and expire cached metadata.
fn upstream_cache_entry_is_fresh(
    entry: &crate::state::OidcUpstreamMetadataCacheEntry,
    source: &IdentitySource,
) -> bool {
    entry.source_updated_at == source.updated_at
        && Utc::now()
            .signed_duration_since(entry.fetched_at)
            .num_seconds()
            < OIDC_UPSTREAM_METADATA_CACHE_TTL_SECONDS
}

/// Return validated Discovery metadata without refetching a live source within the cache window.
async fn fetch_cached_oidc_discovery(
    state: &AppState,
    source: &IdentitySource,
    config: &crate::models::OidcUpstreamConfig,
    client: &reqwest::Client,
) -> Result<OidcUpstreamDiscovery, AuthError> {
    if let Some(discovery) = state
        .oidc_upstream_metadata_cache
        .read()
        .await
        .get(&source.id)
        .filter(|entry| upstream_cache_entry_is_fresh(entry, source))
        .map(|entry| entry.discovery.clone())
    {
        return Ok(discovery);
    }

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
    state.oidc_upstream_metadata_cache.write().await.insert(
        source.id.clone(),
        crate::state::OidcUpstreamMetadataCacheEntry {
            source_updated_at: source.updated_at,
            fetched_at: Utc::now(),
            discovery: discovery.clone(),
            jwks: None,
        },
    );
    Ok(discovery)
}

/// Return cached JWKS and refresh it explicitly when a rotated signing key is unavailable.
async fn fetch_cached_oidc_jwks(
    state: &AppState,
    source: &IdentitySource,
    discovery: &OidcUpstreamDiscovery,
    client: &reqwest::Client,
    force_refresh: bool,
) -> Result<crate::models::OidcUpstreamJwks, AuthError> {
    if !force_refresh {
        if let Some(jwks) = state
            .oidc_upstream_metadata_cache
            .read()
            .await
            .get(&source.id)
            .filter(|entry| {
                upstream_cache_entry_is_fresh(entry, source)
                    && entry.discovery.jwks_uri == discovery.jwks_uri
            })
            .and_then(|entry| entry.jwks.clone())
        {
            return Ok(jwks);
        }
    }

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
    state.oidc_upstream_metadata_cache.write().await.insert(
        source.id.clone(),
        crate::state::OidcUpstreamMetadataCacheEntry {
            source_updated_at: source.updated_at,
            fetched_at: Utc::now(),
            discovery: discovery.clone(),
            jwks: Some(jwks.clone()),
        },
    );
    Ok(jwks)
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

/// Normalize API policy fields without accepting claim-derived organization selection.
fn normalize_identity_source_policy(
    allowed_user_class: Option<&str>,
    organization_strategy: Option<&str>,
    organization_id: Option<&str>,
) -> Result<(String, String, Option<String>), AuthError> {
    let allowed_user_class = allowed_user_class
        .unwrap_or(IDENTITY_SOURCE_USER_CLASS_EXTERNAL_CUSTOMER)
        .trim()
        .to_ascii_lowercase();
    if !crate::models::is_valid_identity_source_user_class(&allowed_user_class) {
        return Err(AuthError::InvalidRequest(
            "allowed_user_class must be external_customer or internal_employee".to_string(),
        ));
    }
    let organization_strategy = organization_strategy
        .unwrap_or(IDENTITY_SOURCE_ORGANIZATION_STRATEGY_NONE)
        .trim()
        .to_ascii_lowercase();
    if !crate::models::is_valid_identity_source_organization_strategy(&organization_strategy) {
        return Err(AuthError::InvalidRequest(
            "organization_strategy must be none or fixed".to_string(),
        ));
    }
    let organization_id = organization_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    match (organization_strategy.as_str(), organization_id.as_ref()) {
        (IDENTITY_SOURCE_ORGANIZATION_STRATEGY_NONE, None)
        | (IDENTITY_SOURCE_ORGANIZATION_STRATEGY_FIXED, Some(_)) => {}
        (IDENTITY_SOURCE_ORGANIZATION_STRATEGY_NONE, Some(_)) => {
            return Err(AuthError::InvalidRequest(
                "organization_id must be omitted when organization_strategy is none".to_string(),
            ));
        }
        (IDENTITY_SOURCE_ORGANIZATION_STRATEGY_FIXED, None) => {
            return Err(AuthError::InvalidRequest(
                "organization_id is required when organization_strategy is fixed".to_string(),
            ));
        }
        _ => unreachable!("identity source strategy was validated above"),
    }
    Ok((allowed_user_class, organization_strategy, organization_id))
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

/// Convert caller-correctable source policy failures into stable request errors.
fn map_identity_source_persistence_error(error: anyhow::Error) -> AuthError {
    match error.to_string().as_str() {
        "identity_source_allowed_user_class_invalid"
        | "identity_source_organization_policy_invalid"
        | "identity_source_organization_not_found"
        | "identity_source_organization_not_active"
        | "identity_source_external_customer_requires_customer_organization"
        | "identity_source_internal_employee_requires_internal_organization" => {
            AuthError::InvalidRequest(error.to_string())
        }
        _ => AuthError::DatabaseError(error.to_string()),
    }
}

/// Build the stable external-provider key used to keep one source's subjects separate from another.
fn oidc_mapping_provider(source: &IdentitySource) -> String {
    format!("oidc_upstream:{}", source.id)
}

/// Reject a callback when an administrator changed its source trust policy mid-flight.
fn identity_source_trust_is_unchanged(
    transaction_source: &IdentitySource,
    current_source: &IdentitySource,
) -> bool {
    current_source.active
        && current_source.source_type == "oidc_upstream"
        && transaction_source.config == current_source.config
        && transaction_source.claim_mapping == current_source.claim_mapping
        && transaction_source.allowed_user_class == current_source.allowed_user_class
        && transaction_source.organization_strategy == current_source.organization_strategy
        && transaction_source.organization_id == current_source.organization_id
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
    let observed_email_verified = mapping
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("email_verified"))
        .and_then(Value::as_bool);
    if observed_email == Some(profile.email.as_str())
        && observed_email_verified == Some(profile.email_verified)
    {
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
        let event_type = if observed_email == Some(profile.email.as_str()) {
            "identity_source.email_verification_observed"
        } else {
            "identity_source.email_change_observed"
        };
        crate::db::create_audit_log(
            db,
            event_type,
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

/// Return true only when a signed upstream profile verifies the exact local email.
fn upstream_email_matches_local(profile: &OidcUpstreamProfile, local_email: &str) -> bool {
    profile.email_verified && profile.email.eq_ignore_ascii_case(local_email.trim())
}

/// Promote a local email only when the signed upstream profile matches it exactly.
async fn apply_upstream_email_verification(
    db: &sqlx::PgPool,
    source: &IdentitySource,
    profile: &OidcUpstreamProfile,
    user: &crate::models::User,
) -> Result<(), AuthError> {
    if !upstream_email_matches_local(profile, &user.email) {
        return Ok(());
    }
    let actor = format!("identity_source:{}", source.id);
    crate::db::mark_user_email_verified(db, &user.id, Some(&actor))
        .await
        .map_err(|_| {
            AuthError::DatabaseError("Failed to persist email verification".to_string())
        })?;
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
        if user.user_class != source.allowed_user_class {
            return Err(AuthError::Forbidden);
        }
        if source.organization_strategy == IDENTITY_SOURCE_ORGANIZATION_STRATEGY_FIXED
            && identity_db::identity_source_login_organization(db, source, &user.id)
                .await
                .map_err(|_| {
                    AuthError::DatabaseError(
                        "Failed to validate identity source organization".to_string(),
                    )
                })?
                .is_none()
        {
            return Err(AuthError::Forbidden);
        }
        record_oidc_email_change(db, source, profile, &mapping).await?;
        apply_upstream_email_verification(db, source, profile, &user).await?;
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
        if user.user_class != source.allowed_user_class {
            return Err(AuthError::Conflict(
                "The existing Keylo account is not eligible for this identity source".to_string(),
            ));
        }
        if source.organization_strategy == IDENTITY_SOURCE_ORGANIZATION_STRATEGY_FIXED
            && identity_db::identity_source_login_organization(db, source, &user.id)
                .await
                .map_err(|_| {
                    AuthError::DatabaseError(
                        "Failed to validate identity source organization".to_string(),
                    )
                })?
                .is_none()
        {
            return Err(AuthError::Forbidden);
        }
        create_oidc_user_mapping(db, source, profile, &user.id).await?;
        apply_upstream_email_verification(db, source, profile, &user).await?;
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
    let user = crate::db::create_user_with_email_verified_as_class(
        db,
        &username,
        &profile.email,
        None,
        profile.email_verified,
        &source.allowed_user_class,
    )
    .await
    .map_err(|error| {
        if is_unique_violation(error.as_ref()) {
            AuthError::Conflict("OIDC account conflicts with an existing Keylo user".to_string())
        } else {
            AuthError::DatabaseError("Failed to create JIT OIDC user".to_string())
        }
    })?;
    if let Err(error) = identity_db::ensure_identity_source_membership(db, source, &user.id).await {
        crate::db::delete_user(db, &user.id, None)
            .await
            .map_err(|_| {
                AuthError::DatabaseError(
                    "Failed to clean up JIT user after organization assignment".to_string(),
                )
            })?;
        return Err(AuthError::DatabaseError(format!(
            "Failed to assign JIT identity source organization: {error}"
        )));
    }
    if let Err(error) = create_oidc_user_mapping(db, source, profile, &user.id).await {
        crate::db::delete_user(db, &user.id, None)
            .await
            .map_err(|_| {
                AuthError::DatabaseError("Failed to clean up conflicting JIT OIDC user".to_string())
            })?;
        return Err(error);
    }
    Ok(user)
}

pub async fn list_identity_sources(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AuthError> {
    let db = require_db(&state)?;
    let has_explicit_pagination = params.contains_key("limit") || params.contains_key("offset");
    let requested_limit = params
        .get("limit")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    let requested_offset = params
        .get("offset")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0)
        .max(0);
    let (sources, has_more, limit, offset) = if has_explicit_pagination {
        let (sources, has_more) =
            identity_db::list_identity_sources_page(db, requested_limit, requested_offset)
                .await
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        (sources, has_more, requested_limit, requested_offset)
    } else {
        let sources = identity_db::list_identity_sources(db)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let count = sources.len() as i64;
        (sources, false, count, 0)
    };

    Ok(Json(json!({
        "identity_sources": sources
            .into_iter()
            .map(IdentitySource::redacted_for_response)
            .collect::<Vec<_>>(),
        "pagination": {
            "limit": limit,
            "offset": offset,
            "has_more": has_more,
            "next_offset": has_more.then_some(offset + limit),
        }
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
    let (allowed_user_class, organization_strategy, organization_id) =
        normalize_identity_source_policy(
            payload.allowed_user_class.as_deref(),
            payload.organization_strategy.as_deref(),
            payload.organization_id.as_deref(),
        )?;

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
            allowed_user_class: &allowed_user_class,
            organization_strategy: &organization_strategy,
            organization_id: organization_id.as_deref(),
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
            map_identity_source_persistence_error(e)
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
    let client = oidc_upstream_http_client()?;
    let discovery = fetch_cached_oidc_discovery(&state, &source, &config, &client).await?;
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
    let client = oidc_upstream_http_client()?;
    let discovery = fetch_cached_oidc_discovery(&state, &source, &config, &client).await?;
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
    let client = oidc_upstream_http_client()?;
    let discovery = fetch_cached_oidc_discovery(&state, &source, &config, &client).await?;
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
    let jwks = fetch_cached_oidc_jwks(&state, &source, &discovery, &client, false).await?;
    let claims = match crate::models::verify_oidc_upstream_id_token(id_token, &jwks) {
        Ok(claims) => claims,
        Err(error) if error == "Upstream ID Token signing key is unavailable" => {
            let refreshed_jwks =
                fetch_cached_oidc_jwks(&state, &source, &discovery, &client, true).await?;
            crate::models::verify_oidc_upstream_id_token(id_token, &refreshed_jwks)
                .map_err(AuthError::InvalidRequest)?
        }
        Err(error) => return Err(AuthError::InvalidRequest(error)),
    };
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
    let current_source = identity_db::get_identity_source(db, &source.id)
        .await
        .map_err(|_| AuthError::DatabaseError("Failed to revalidate identity source".to_string()))?
        .filter(|current| identity_source_trust_is_unchanged(&source, current))
        .ok_or(AuthError::Forbidden)?;
    let profile =
        crate::models::oidc_upstream_profile_with_mapping(&claims, &current_source.claim_mapping)
            .map_err(AuthError::InvalidRequest)?;
    let user = resolve_oidc_upstream_user(db, &current_source, &profile).await?;
    let organization_id =
        identity_db::identity_source_login_organization(db, &current_source, &user.id)
            .await
            .map_err(|_| {
                AuthError::DatabaseError(
                    "Failed to resolve identity source organization".to_string(),
                )
            })?;
    let tokens = crate::handlers::issue_external_user_session(
        &state,
        db,
        &user,
        &oidc_mapping_provider(&current_source),
        organization_id.as_deref(),
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
    let existing = identity_db::get_identity_source(db, &source_id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        .ok_or(AuthError::NotFound)?;
    if let Some(config) = config.as_mut() {
        preserve_redacted_identity_secrets(&existing.config, config);
        validate_identity_source_config(&existing.source_type, config)?;
    }
    if let Some(claim_mapping) = claim_mapping.as_ref() {
        validate_identity_source_claim_mapping(&existing.source_type, claim_mapping)?;
    }
    let effective_strategy = payload
        .organization_strategy
        .as_deref()
        .unwrap_or(&existing.organization_strategy);
    let effective_organization_id = if effective_strategy
        .trim()
        .eq_ignore_ascii_case(IDENTITY_SOURCE_ORGANIZATION_STRATEGY_NONE)
    {
        payload.organization_id.as_deref()
    } else {
        payload
            .organization_id
            .as_deref()
            .or(existing.organization_id.as_deref())
    };
    let (allowed_user_class, organization_strategy, organization_id) =
        normalize_identity_source_policy(
            payload
                .allowed_user_class
                .as_deref()
                .or(Some(&existing.allowed_user_class)),
            Some(effective_strategy),
            effective_organization_id,
        )?;
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
            allowed_user_class: Some(&allowed_user_class),
            organization_strategy: Some(&organization_strategy),
            organization_id: organization_id.as_deref(),
        },
        Some(&claims.sub),
    )
    .await
    .map_err(map_identity_source_persistence_error)?
    .ok_or(AuthError::NotFound)?;

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
    fn identity_source_policy_defaults_to_external_without_an_organization() {
        let policy = normalize_identity_source_policy(None, None, None).unwrap();

        assert_eq!(
            policy,
            ("external_customer".to_string(), "none".to_string(), None)
        );
    }

    #[test]
    fn identity_source_policy_rejects_claim_derived_organization_context() {
        let error = normalize_identity_source_policy(
            Some("external_customer"),
            Some("claim"),
            Some("org-customer"),
        )
        .unwrap_err();

        assert!(matches!(error, AuthError::InvalidRequest(_)));
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

    #[tokio::test]
    async fn upstream_metadata_cache_uses_source_version_and_cached_jwks() {
        let state = AppState::default();
        let source_updated_at = chrono::Utc::now();
        let source = IdentitySource {
            id: "cache-source".to_string(),
            name: "cache-source".to_string(),
            source_type: "oidc_upstream".to_string(),
            display_name: "Cache source".to_string(),
            description: None,
            config: json!({}),
            claim_mapping: json!({}),
            jit_enabled: true,
            auto_link_enabled: true,
            active: true,
            allowed_user_class: "external_customer".to_string(),
            organization_strategy: "none".to_string(),
            organization_id: None,
            created_at: source_updated_at,
            updated_at: source_updated_at,
        };
        let config: crate::models::OidcUpstreamConfig = serde_json::from_value(json!({
            "issuer": "https://127.0.0.1:1",
            "client_id": "cache-client",
            "client_secret": "cache-secret",
            "redirect_uri": "https://keylo.example.test/callback"
        }))
        .unwrap();
        let discovery = OidcUpstreamDiscovery {
            issuer: config.issuer.clone(),
            authorization_endpoint: "https://127.0.0.1:1/authorize".to_string(),
            token_endpoint: "https://127.0.0.1:1/token".to_string(),
            jwks_uri: "https://127.0.0.1:1/jwks".to_string(),
            userinfo_endpoint: None,
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: None,
            token_endpoint_auth_methods_supported: None,
            id_token_signing_alg_values_supported: None,
        };
        let jwks = crate::models::OidcUpstreamJwks { keys: Vec::new() };
        state.oidc_upstream_metadata_cache.write().await.insert(
            source.id.clone(),
            crate::state::OidcUpstreamMetadataCacheEntry {
                source_updated_at,
                fetched_at: chrono::Utc::now(),
                discovery: discovery.clone(),
                jwks: Some(jwks.clone()),
            },
        );
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(20))
            .build()
            .unwrap();

        assert_eq!(
            fetch_cached_oidc_discovery(&state, &source, &config, &client)
                .await
                .unwrap()
                .jwks_uri,
            discovery.jwks_uri
        );
        assert!(
            fetch_cached_oidc_jwks(&state, &source, &discovery, &client, false)
                .await
                .unwrap()
                .keys
                .is_empty()
        );

        let changed_source = IdentitySource {
            updated_at: source_updated_at + chrono::Duration::seconds(1),
            ..source
        };
        assert!(matches!(
            fetch_cached_oidc_discovery(&state, &changed_source, &config, &client).await,
            Err(AuthError::InvalidRequest(_))
        ));
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
            allowed_user_class: "external_customer".to_string(),
            organization_strategy: "none".to_string(),
            organization_id: None,
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

    #[test]
    fn upstream_email_verification_requires_a_matching_verified_email() {
        let verified = OidcUpstreamProfile {
            external_subject: "employee-123".to_string(),
            username: "alice".to_string(),
            email: "alice@example.com".to_string(),
            email_verified: true,
        };
        assert!(upstream_email_matches_local(
            &verified,
            " Alice@Example.COM "
        ));

        let unverified = OidcUpstreamProfile {
            email_verified: false,
            ..verified.clone()
        };
        assert!(!upstream_email_matches_local(
            &unverified,
            "alice@example.com"
        ));
        assert!(!upstream_email_matches_local(
            &verified,
            "other@example.com"
        ));
    }
}

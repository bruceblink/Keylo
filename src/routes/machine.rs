use axum::{
    extract::{Path, Query, State},
    response::Json,
    routing::{delete, get, post},
    Router,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeSet;

use crate::{
    db::machine as machine_db,
    errors::{is_unique_violation, AuthError},
    models::{
        Claims, CreateDeviceRequest, CreateMachineCredentialRequest,
        MachineCredentialSecretResponse, RevokeMachineCredentialRequest,
        RotateMachineCredentialRequest, UpdateDeviceRequest,
    },
    routes::organization,
    state::AppState,
};

/// Optional platform filter. Organization routes always take scope from the path.
#[derive(Debug, Deserialize)]
struct MachineScopeQuery {
    organization_id: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct MachinePaginationQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}

/// Mounts platform-admin machine identity and API-key lifecycle endpoints.
pub fn machine_admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/admin/devices",
            get(list_platform_devices_handler).post(create_platform_device_handler),
        )
        .route(
            "/v1/admin/devices/{device_id}",
            get(get_platform_device_handler).put(update_platform_device_handler),
        )
        .route(
            "/v1/admin/principals/{principal_id}/api-keys",
            get(list_platform_api_keys_handler).post(create_platform_api_key_handler),
        )
        .route(
            "/v1/admin/principals/{principal_id}/api-keys/{key_id}/rotate",
            post(rotate_platform_api_key_handler),
        )
        .route(
            "/v1/admin/principals/{principal_id}/api-keys/{key_id}",
            delete(revoke_platform_api_key_handler),
        )
}

/// Mounts organization-local machine management. Authorization comes from the
/// signed active organization context, never from a caller-supplied body field.
pub fn organization_machine_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/organizations/{organization_id}/devices",
            get(list_organization_devices_handler).post(create_organization_device_handler),
        )
        .route(
            "/v1/organizations/{organization_id}/devices/{device_id}",
            get(get_organization_device_handler).put(update_organization_device_handler),
        )
        .route(
            "/v1/organizations/{organization_id}/principals/{principal_id}/api-keys",
            get(list_organization_api_keys_handler).post(create_organization_api_key_handler),
        )
        .route(
            "/v1/organizations/{organization_id}/principals/{principal_id}/api-keys/{key_id}/rotate",
            post(rotate_organization_api_key_handler),
        )
        .route(
            "/v1/organizations/{organization_id}/principals/{principal_id}/api-keys/{key_id}",
            delete(revoke_organization_api_key_handler),
        )
}

fn require_db(state: &AppState) -> Result<&sqlx::PgPool, AuthError> {
    state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))
}

fn normalize_organization_id(value: Option<String>) -> Result<Option<String>, AuthError> {
    match value {
        Some(value) if value.trim().is_empty() => Err(AuthError::InvalidRequest(
            "organization_id must not be empty".to_string(),
        )),
        Some(value) => Ok(Some(value.trim().to_string())),
        None => Ok(None),
    }
}

fn required_value<'a>(value: &'a str, field: &str) -> Result<&'a str, AuthError> {
    let value = value.trim();
    if value.is_empty() {
        Err(AuthError::InvalidRequest(format!("{field} is required")))
    } else {
        Ok(value)
    }
}

/// Normalizes narrow capability values before storing them as credential limits.
fn normalize_capabilities(
    field: &str,
    values: &[String],
    allow_wildcard: bool,
) -> Result<Vec<String>, AuthError> {
    let mut normalized = BTreeSet::new();
    for value in values {
        let value = value.trim();
        if value.is_empty()
            || (!allow_wildcard && value == "*")
            || !value.chars().all(|character| {
                character.is_ascii_alphanumeric()
                    || matches!(character, ':' | '-' | '_' | '.' | '*')
            })
        {
            return Err(AuthError::InvalidRequest(format!("invalid {field}")));
        }
        normalized.insert(value.to_string());
    }
    if normalized.is_empty() {
        return Err(AuthError::InvalidRequest(format!(
            "{field} must not be empty"
        )));
    }
    Ok(normalized.into_iter().collect())
}

fn parse_future_expiry(value: Option<&str>) -> Result<Option<NaiveDateTime>, AuthError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let expires_at = DateTime::parse_from_rfc3339(value)
        .map_err(|_| AuthError::InvalidRequest("expires_at must be RFC3339".to_string()))?
        .with_timezone(&Utc)
        .naive_utc();
    if expires_at <= Utc::now().naive_utc() {
        return Err(AuthError::InvalidRequest(
            "expires_at must be in the future".to_string(),
        ));
    }
    Ok(Some(expires_at))
}

fn map_machine_error(error: anyhow::Error) -> AuthError {
    if is_unique_violation(error.as_ref()) {
        return AuthError::Conflict("Machine identity already exists".to_string());
    }
    match error.to_string().as_str() {
        "machine_principal_not_found" | "machine_scope_mismatch" => AuthError::NotFound,
        "machine_scope_invalid"
        | "machine_principal_type_invalid"
        | "machine_principal_scope_invalid" => {
            AuthError::InvalidRequest("Invalid machine principal scope".to_string())
        }
        "machine_principal_inactive"
        | "machine_organization_context_inactive"
        | "machine_organization_membership_inactive" => {
            AuthError::Conflict("Machine identity is not active in this scope".to_string())
        }
        message => AuthError::DatabaseError(message.to_string()),
    }
}

/// Conceals tenant and Principal existence from an organization manager.
fn map_delegated_machine_error(error: anyhow::Error) -> AuthError {
    let message = error.to_string();
    if is_unique_violation(error.as_ref()) {
        return AuthError::Conflict("Machine identity already exists".to_string());
    }
    match message.as_str() {
        "machine_scope_invalid"
        | "machine_principal_type_invalid"
        | "machine_principal_scope_invalid" => {
            AuthError::InvalidRequest("Invalid machine principal scope".to_string())
        }
        "organization_not_found"
        | "organization_not_active"
        | "organization_manager_principal_not_found"
        | "organization_manager_membership_not_found"
        | "organization_manager_membership_not_active"
        | "organization_manager_principal_inactive"
        | "organization_manager_requires_user_principal"
        | "organization_manager_user_not_found"
        | "organization_manager_user_class_invalid"
        | "organization_manager_role_required"
        | "organization_target_principal_not_found"
        | "organization_target_membership_not_active"
        | "organization_target_principal_inactive"
        | "machine_principal_not_found"
        | "machine_scope_mismatch"
        | "machine_principal_inactive"
        | "machine_organization_context_inactive"
        | "machine_organization_membership_inactive" => AuthError::Forbidden,
        _ => AuthError::DatabaseError(message),
    }
}

/// Writes metadata-only audit evidence; API keys are deliberately never included.
async fn audit_machine_event(
    db: &sqlx::PgPool,
    event_type: &str,
    actor: Option<&str>,
    detail: String,
) {
    if let Err(error) = crate::db::create_audit_log(db, event_type, actor, Some(&detail)).await {
        tracing::warn!(event_type, error = %error, "Failed to write machine audit log");
    }
}

async fn get_platform_device_handler(
    State(state): State<AppState>,
    Path(device_id): Path<String>,
    Query(query): Query<MachineScopeQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = require_db(&state)?;
    let organization_id = normalize_organization_id(query.organization_id)?;
    let device = machine_db::get_device_in_scope(db, organization_id.as_deref(), &device_id)
        .await
        .map_err(map_machine_error)?
        .ok_or(AuthError::NotFound)?;
    Ok(Json(json!({ "success": true, "data": device })))
}

async fn list_platform_devices_handler(
    State(state): State<AppState>,
    Query(query): Query<MachineScopeQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = require_db(&state)?;
    let organization_id = normalize_organization_id(query.organization_id)?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);
    let (devices, has_more) =
        machine_db::list_devices_in_scope_page(db, organization_id.as_deref(), limit, offset)
            .await
            .map_err(map_machine_error)?;
    Ok(Json(json!({
        "success": true,
        "data": devices,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "has_more": has_more,
            "next_offset": has_more.then_some(offset + limit),
        }
    })))
}

async fn create_platform_device_handler(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<CreateDeviceRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = require_db(&state)?;
    let device_id = required_value(&payload.device_id, "device_id")?;
    let display_name = required_value(&payload.display_name, "display_name")?;
    let organization_id = normalize_organization_id(payload.organization_id)?;
    let device = machine_db::create_device(
        db,
        machine_db::CreateDeviceParams {
            device_id,
            display_name,
            organization_id: organization_id.as_deref(),
        },
    )
    .await
    .map_err(map_machine_error)?;
    audit_machine_event(
        db,
        "machine.device.created",
        Some(&claims.sub),
        format!(
            "principal_id={},device_id={},organization_id={}",
            device.principal_id,
            device.device_id,
            device.organization_id.as_deref().unwrap_or("-")
        ),
    )
    .await;
    Ok(Json(json!({ "success": true, "data": device })))
}

async fn update_platform_device_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(device_id): Path<String>,
    Query(query): Query<MachineScopeQuery>,
    Json(payload): Json<UpdateDeviceRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = require_db(&state)?;
    let organization_id = normalize_organization_id(query.organization_id)?;
    let display_name = payload
        .display_name
        .as_deref()
        .map(|value| required_value(value, "display_name"))
        .transpose()?;
    if display_name.is_none() && payload.active.is_none() {
        return Err(AuthError::InvalidRequest(
            "display_name or active is required".to_string(),
        ));
    }
    let updated = machine_db::update_device_in_scope(
        db,
        organization_id.as_deref(),
        &device_id,
        machine_db::UpdateDeviceParams {
            display_name,
            active: payload.active,
        },
    )
    .await
    .map_err(map_machine_error)?;
    if !updated {
        return Err(AuthError::NotFound);
    }
    let device = machine_db::get_device_in_scope(db, organization_id.as_deref(), &device_id)
        .await
        .map_err(map_machine_error)?
        .ok_or(AuthError::NotFound)?;
    audit_machine_event(
        db,
        "machine.device.updated",
        Some(&claims.sub),
        format!(
            "principal_id={},organization_id={}",
            device.principal_id,
            device.organization_id.as_deref().unwrap_or("-")
        ),
    )
    .await;
    Ok(Json(json!({ "success": true, "data": device })))
}

async fn list_platform_api_keys_handler(
    State(state): State<AppState>,
    Path(principal_id): Path<String>,
    Query(query): Query<MachineScopeQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = require_db(&state)?;
    let organization_id = normalize_organization_id(query.organization_id)?;
    require_machine_scope(db, &principal_id, organization_id.as_deref()).await?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);
    let (credentials, has_more) = machine_db::list_machine_credentials_in_scope_page(
        db,
        &principal_id,
        organization_id.as_deref(),
        limit,
        offset,
    )
    .await
    .map_err(map_machine_error)?;
    Ok(Json(json!({
        "success": true,
        "data": credentials,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "has_more": has_more,
            "next_offset": has_more.then_some(offset + limit),
        }
    })))
}

async fn create_platform_api_key_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(principal_id): Path<String>,
    Json(payload): Json<CreateMachineCredentialRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = require_db(&state)?;
    let organization_id = normalize_organization_id(payload.organization_id)?;
    let response = create_api_key(
        db,
        &principal_id,
        organization_id.as_deref(),
        claims.principal_id.as_deref(),
        payload.expires_at.as_deref(),
        &payload.allowed_scopes,
        &payload.allowed_audiences,
    )
    .await?;
    audit_api_key_event(db, "machine.api_key.created", &claims, &response).await;
    Ok(Json(json!({ "success": true, "data": response })))
}

async fn rotate_platform_api_key_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((principal_id, key_id)): Path<(String, String)>,
    Query(query): Query<MachineScopeQuery>,
    Json(payload): Json<RotateMachineCredentialRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = require_db(&state)?;
    let organization_id = normalize_organization_id(query.organization_id)?;
    let response = rotate_api_key(
        db,
        &principal_id,
        organization_id.as_deref(),
        &key_id,
        claims.principal_id.as_deref(),
        &payload,
    )
    .await?
    .ok_or(AuthError::NotFound)?;
    audit_api_key_event(db, "machine.api_key.rotated", &claims, &response).await;
    Ok(Json(json!({ "success": true, "data": response })))
}

async fn revoke_platform_api_key_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((principal_id, key_id)): Path<(String, String)>,
    Query(query): Query<MachineScopeQuery>,
    Json(payload): Json<RevokeMachineCredentialRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = require_db(&state)?;
    let organization_id = normalize_organization_id(query.organization_id)?;
    let revoked = machine_db::revoke_machine_credential_in_scope(
        db,
        &principal_id,
        organization_id.as_deref(),
        &key_id,
        payload.reason.as_deref(),
    )
    .await
    .map_err(map_machine_error)?;
    if !revoked {
        return Err(AuthError::NotFound);
    }
    audit_machine_event(
        db,
        "machine.api_key.revoked",
        Some(&claims.sub),
        format!(
            "key_id={key_id},principal_id={principal_id},organization_id={}",
            organization_id.as_deref().unwrap_or("-")
        ),
    )
    .await;
    Ok(Json(json!({ "success": true })))
}

async fn list_organization_devices_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    Query(query): Query<MachinePaginationQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let actor = organization::require_delegated_manager(&state, &claims, &organization_id).await?;
    let db = require_db(&state)?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);
    let (devices, has_more) =
        machine_db::list_devices_in_scope_page(db, Some(&organization_id), limit, offset)
            .await
            .map_err(map_delegated_machine_error)?;
    audit_machine_event(
        db,
        "machine.device.listed",
        Some(&actor.id),
        format!("organization_id={organization_id},count={}", devices.len()),
    )
    .await;
    Ok(Json(json!({
        "success": true,
        "data": devices,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "has_more": has_more,
            "next_offset": has_more.then_some(offset + limit),
        }
    })))
}

async fn get_organization_device_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((organization_id, device_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AuthError> {
    organization::require_delegated_manager(&state, &claims, &organization_id).await?;
    let db = require_db(&state)?;
    let device = machine_db::get_device_in_scope(db, Some(&organization_id), &device_id)
        .await
        .map_err(map_delegated_machine_error)?
        .ok_or(AuthError::NotFound)?;
    Ok(Json(json!({ "success": true, "data": device })))
}

async fn create_organization_device_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    Json(payload): Json<CreateDeviceRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let actor = organization::require_delegated_manager(&state, &claims, &organization_id).await?;
    organization::require_delegated_mfa(&state, &claims).await?;
    if payload.organization_id.is_some() {
        return Err(AuthError::InvalidRequest(
            "organization_id is derived from the path".to_string(),
        ));
    }
    let db = require_db(&state)?;
    let device_id = required_value(&payload.device_id, "device_id")?;
    let display_name = required_value(&payload.display_name, "display_name")?;
    let device = machine_db::create_device_as_organization_manager(
        db,
        &organization_id,
        &actor.id,
        machine_db::CreateDeviceParams {
            device_id,
            display_name,
            organization_id: Some(&organization_id),
        },
    )
    .await
    .map_err(map_delegated_machine_error)?;
    audit_machine_event(
        db,
        "machine.device.created",
        Some(&actor.id),
        format!(
            "principal_id={},device_id={},organization_id={organization_id}",
            device.principal_id, device.device_id
        ),
    )
    .await;
    Ok(Json(json!({ "success": true, "data": device })))
}

async fn update_organization_device_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((organization_id, device_id)): Path<(String, String)>,
    Json(payload): Json<UpdateDeviceRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let actor = organization::require_delegated_manager(&state, &claims, &organization_id).await?;
    organization::require_delegated_mfa(&state, &claims).await?;
    let display_name = payload
        .display_name
        .as_deref()
        .map(|value| required_value(value, "display_name"))
        .transpose()?;
    if display_name.is_none() && payload.active.is_none() {
        return Err(AuthError::InvalidRequest(
            "display_name or active is required".to_string(),
        ));
    }
    let db = require_db(&state)?;
    let updated = machine_db::update_device_as_organization_manager(
        db,
        &organization_id,
        &actor.id,
        &device_id,
        machine_db::UpdateDeviceParams {
            display_name,
            active: payload.active,
        },
    )
    .await
    .map_err(map_delegated_machine_error)?;
    if !updated {
        return Err(AuthError::NotFound);
    }
    let device = machine_db::get_device_in_scope(db, Some(&organization_id), &device_id)
        .await
        .map_err(map_delegated_machine_error)?
        .ok_or(AuthError::NotFound)?;
    audit_machine_event(
        db,
        "machine.device.updated",
        Some(&actor.id),
        format!(
            "principal_id={},organization_id={organization_id}",
            device.principal_id
        ),
    )
    .await;
    Ok(Json(json!({ "success": true, "data": device })))
}

async fn list_organization_api_keys_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((organization_id, principal_id)): Path<(String, String)>,
    Query(query): Query<MachinePaginationQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    organization::require_delegated_manager(&state, &claims, &organization_id).await?;
    let db = require_db(&state)?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);
    let (credentials, has_more) = machine_db::list_machine_credentials_in_scope_page(
        db,
        &principal_id,
        Some(&organization_id),
        limit,
        offset,
    )
    .await
    .map_err(map_delegated_machine_error)?;
    Ok(Json(json!({
        "success": true,
        "data": credentials,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "has_more": has_more,
            "next_offset": has_more.then_some(offset + limit),
        }
    })))
}

async fn create_organization_api_key_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((organization_id, principal_id)): Path<(String, String)>,
    Json(payload): Json<CreateMachineCredentialRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let actor = organization::require_delegated_manager(&state, &claims, &organization_id).await?;
    organization::require_delegated_mfa(&state, &claims).await?;
    if payload.organization_id.is_some() {
        return Err(AuthError::InvalidRequest(
            "organization_id is derived from the path".to_string(),
        ));
    }
    let db = require_db(&state)?;
    let scopes = normalize_capabilities("allowed_scopes", &payload.allowed_scopes, false)?;
    let audiences = normalize_capabilities("allowed_audiences", &payload.allowed_audiences, true)?;
    let expires_at = parse_future_expiry(payload.expires_at.as_deref())?;
    let response = machine_db::create_machine_credential_as_organization_manager(
        db,
        &organization_id,
        &actor.id,
        machine_db::CreateMachineCredentialParams {
            principal_id: &principal_id,
            organization_id: Some(&organization_id),
            created_by_principal_id: Some(&actor.id),
            expires_at,
            allowed_scopes: &scopes,
            allowed_audiences: &audiences,
        },
    )
    .await
    .map_err(map_delegated_machine_error)?;
    audit_api_key_event(db, "machine.api_key.created", &claims, &response).await;
    Ok(Json(json!({ "success": true, "data": response })))
}

async fn rotate_organization_api_key_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((organization_id, principal_id, key_id)): Path<(String, String, String)>,
    Json(payload): Json<RotateMachineCredentialRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let actor = organization::require_delegated_manager(&state, &claims, &organization_id).await?;
    organization::require_delegated_mfa(&state, &claims).await?;
    let db = require_db(&state)?;
    let expires_at = parse_future_expiry(payload.expires_at.as_deref())?;
    let scopes = payload
        .allowed_scopes
        .as_deref()
        .map(|values| normalize_capabilities("allowed_scopes", values, false))
        .transpose()?;
    let audiences = payload
        .allowed_audiences
        .as_deref()
        .map(|values| normalize_capabilities("allowed_audiences", values, true))
        .transpose()?;
    let response = machine_db::rotate_machine_credential_as_organization_manager(
        db,
        &organization_id,
        &actor.id,
        machine_db::RotateMachineCredentialParams {
            principal_id: &principal_id,
            organization_id: Some(&organization_id),
            key_id: &key_id,
            created_by_principal_id: Some(&actor.id),
            expires_at,
            allowed_scopes: scopes.as_deref(),
            allowed_audiences: audiences.as_deref(),
        },
    )
    .await
    .map_err(map_delegated_machine_error)?
    .ok_or(AuthError::NotFound)?;
    audit_api_key_event(db, "machine.api_key.rotated", &claims, &response).await;
    Ok(Json(json!({ "success": true, "data": response })))
}

async fn revoke_organization_api_key_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((organization_id, principal_id, key_id)): Path<(String, String, String)>,
    Json(payload): Json<RevokeMachineCredentialRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let actor = organization::require_delegated_manager(&state, &claims, &organization_id).await?;
    organization::require_delegated_mfa(&state, &claims).await?;
    let db = require_db(&state)?;
    let revoked = machine_db::revoke_machine_credential_as_organization_manager(
        db,
        &organization_id,
        &actor.id,
        &principal_id,
        &key_id,
        payload.reason.as_deref(),
    )
    .await
    .map_err(map_delegated_machine_error)?;
    if !revoked {
        return Err(AuthError::NotFound);
    }
    audit_machine_event(
        db,
        "machine.api_key.revoked",
        Some(&actor.id),
        format!("key_id={key_id},principal_id={principal_id},organization_id={organization_id}"),
    )
    .await;
    Ok(Json(json!({ "success": true })))
}

async fn require_machine_scope(
    db: &sqlx::PgPool,
    principal_id: &str,
    organization_id: Option<&str>,
) -> Result<(), AuthError> {
    let scope = machine_db::get_machine_principal_scope(db, principal_id)
        .await
        .map_err(map_machine_error)?
        .ok_or(AuthError::NotFound)?;
    if scope.organization_id.as_deref() != organization_id {
        return Err(AuthError::NotFound);
    }
    Ok(())
}

async fn create_api_key(
    db: &sqlx::PgPool,
    principal_id: &str,
    organization_id: Option<&str>,
    actor: Option<&str>,
    expires_at: Option<&str>,
    requested_scopes: &[String],
    requested_audiences: &[String],
) -> Result<MachineCredentialSecretResponse, AuthError> {
    let scopes = normalize_capabilities("allowed_scopes", requested_scopes, false)?;
    let audiences = normalize_capabilities("allowed_audiences", requested_audiences, true)?;
    let expires_at = parse_future_expiry(expires_at)?;
    machine_db::create_machine_credential(
        db,
        machine_db::CreateMachineCredentialParams {
            principal_id,
            organization_id,
            created_by_principal_id: actor,
            expires_at,
            allowed_scopes: &scopes,
            allowed_audiences: &audiences,
        },
    )
    .await
    .map_err(map_machine_error)
}

async fn rotate_api_key(
    db: &sqlx::PgPool,
    principal_id: &str,
    organization_id: Option<&str>,
    key_id: &str,
    actor: Option<&str>,
    payload: &RotateMachineCredentialRequest,
) -> Result<Option<MachineCredentialSecretResponse>, AuthError> {
    let expires_at = parse_future_expiry(payload.expires_at.as_deref())?;
    let scopes = payload
        .allowed_scopes
        .as_deref()
        .map(|values| normalize_capabilities("allowed_scopes", values, false))
        .transpose()?;
    let audiences = payload
        .allowed_audiences
        .as_deref()
        .map(|values| normalize_capabilities("allowed_audiences", values, true))
        .transpose()?;
    machine_db::rotate_machine_credential(
        db,
        machine_db::RotateMachineCredentialParams {
            principal_id,
            organization_id,
            key_id,
            created_by_principal_id: actor,
            expires_at,
            allowed_scopes: scopes.as_deref(),
            allowed_audiences: audiences.as_deref(),
        },
    )
    .await
    .map_err(map_machine_error)
}

async fn audit_api_key_event(
    db: &sqlx::PgPool,
    event_type: &str,
    claims: &Claims,
    response: &MachineCredentialSecretResponse,
) {
    audit_machine_event(
        db,
        event_type,
        Some(&claims.sub),
        format!(
            "key_id={},prefix={},principal_id={},organization_id={}",
            response.credential.key_id,
            response.credential.prefix,
            response.credential.principal_id,
            response
                .credential
                .organization_id
                .as_deref()
                .unwrap_or("-")
        ),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_capabilities_are_normalized_and_nonempty() {
        assert_eq!(
            normalize_capabilities(
                "allowed_scopes",
                &[" authorization ".to_string(), "authorization".to_string()],
                false,
            )
            .unwrap(),
            vec!["authorization"]
        );
        assert!(normalize_capabilities("allowed_scopes", &[], false).is_err());
        assert!(normalize_capabilities("allowed_scopes", &["*".to_string()], false).is_err());
    }

    #[test]
    fn expiry_must_be_future_rfc3339() {
        assert!(parse_future_expiry(Some("not-a-time")).is_err());
        assert!(parse_future_expiry(Some("2000-01-01T00:00:00Z")).is_err());
    }
}

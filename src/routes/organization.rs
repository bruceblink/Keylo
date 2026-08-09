use axum::{
    extract::{Path, Query, State},
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeSet;

use crate::{
    db::service as svc_db,
    errors::{is_unique_violation, AuthError},
    models::{
        Claims, CreateOrganizationRequest, InviteOrganizationMemberRequest, OrganizationListQuery,
        OrganizationRoleBindingRequest, Principal, RegisterOrganizationServiceRequest,
        RotateServiceSecretRequest, UpdateOrganizationMembershipRequest,
        UpdateOrganizationServiceRequest, UpdateOrganizationStatusRequest,
        UpsertOrganizationMembershipRequest, USER_CLASS_EXTERNAL_CUSTOMER,
        USER_CLASS_INTERNAL_EMPLOYEE,
    },
    state::AppState,
};

/// Mounts platform-admin organization and membership lifecycle endpoints.
pub fn organization_admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/admin/organizations",
            get(list_organizations_handler).post(create_organization_handler),
        )
        .route(
            "/v1/admin/organizations/{organization_id}",
            get(get_organization_handler),
        )
        .route(
            "/v1/admin/organizations/{organization_id}/status",
            put(update_organization_status_handler),
        )
        .route(
            "/v1/admin/organizations/{organization_id}/memberships",
            get(list_memberships_handler),
        )
        .route(
            "/v1/admin/organizations/{organization_id}/memberships/{principal_id}",
            get(get_membership_handler).put(upsert_membership_handler),
        )
}

/// Mounts organization owner/admin endpoints. These routes use the signed
/// active-organization claim and never grant authority from role bindings.
pub fn organization_member_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/organizations/{organization_id}/memberships",
            get(list_delegated_memberships_handler),
        )
        .route(
            "/v1/organizations/{organization_id}/memberships/invitations",
            post(invite_delegated_member_handler),
        )
        .route(
            "/v1/organizations/{organization_id}/memberships/{principal_id}",
            put(update_delegated_membership_handler),
        )
        .route(
            "/v1/organizations/{organization_id}/memberships/{principal_id}/join",
            post(join_delegated_membership_handler),
        )
        .route(
            "/v1/organizations/{organization_id}/memberships/{principal_id}/roles",
            get(list_delegated_roles_handler).post(assign_delegated_role_handler),
        )
        .route(
            "/v1/organizations/{organization_id}/memberships/{principal_id}/roles/{role_id}",
            delete(revoke_delegated_role_handler),
        )
        .route(
            "/v1/organizations/{organization_id}/services",
            get(list_delegated_services_handler).post(register_delegated_service_handler),
        )
        .route(
            "/v1/organizations/{organization_id}/services/{service_id}",
            get(get_delegated_service_handler).put(update_delegated_service_handler),
        )
        .route(
            "/v1/organizations/{organization_id}/services/{service_id}/rotate-secret",
            post(rotate_delegated_service_secret_handler),
        )
}

fn map_organization_error(error: anyhow::Error) -> AuthError {
    let message = error.to_string();
    match message.as_str() {
        "organization_not_found" | "organization_or_principal_not_found" => AuthError::NotFound,
        "organization_slug_required"
        | "organization_name_required"
        | "organization_not_active"
        | "principal_not_active"
        | "external_customer_requires_customer_organization"
        | "invalid_organization_kind"
        | "invalid_organization_status"
        | "invalid_organization_status_transition"
        | "invalid_organization_membership_status"
        | "invalid_organization_management_role"
        | "role_not_organization_scoped"
        | "role_not_assignable_to_principal_type"
        | "invalid_role_assignable_to" => AuthError::InvalidRequest(message),
        _ if is_unique_violation(error.as_ref()) => {
            AuthError::Conflict("Organization or membership already exists".to_string())
        }
        _ => AuthError::DatabaseError(message),
    }
}

fn require_organization_db(state: &AppState) -> Result<&sqlx::PgPool, AuthError> {
    state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))
}

fn map_delegated_error(error: anyhow::Error) -> AuthError {
    let message = error.to_string();
    if message.starts_with("role_not_assignable_to_principal_type")
        || message.starts_with("invalid_role_assignable_to")
    {
        return AuthError::InvalidRequest(message);
    }
    match message.as_str() {
        // Delegated callers must not learn whether another tenant or member
        // exists merely by changing a path parameter.
        "organization_not_found"
        | "organization_not_active"
        | "organization_manager_principal_not_found"
        | "organization_target_principal_not_found"
        | "organization_manager_membership_not_found"
        | "organization_manager_membership_not_active"
        | "organization_manager_principal_inactive"
        | "organization_manager_requires_user_principal"
        | "organization_manager_user_not_found"
        | "organization_manager_user_class_invalid"
        | "organization_manager_role_required"
        | "organization_target_membership_not_found"
        | "organization_target_membership_not_active"
        | "organization_target_principal_inactive"
        | "organization_target_user_not_found"
        | "organization_target_user_class_invalid"
        | "organization_invitation_not_found"
        | "organization_membership_not_joinable"
        | "organization_join_requires_user_principal"
        | "organization_membership_or_role_not_found_or_inactive"
        | "organization_management_role_requires_user_principal"
        | "organization_owner_role_required" => AuthError::Forbidden,
        "organization_role_not_found" => AuthError::NotFound,
        _ => map_organization_error(error),
    }
}

/// Resolves the human Principal represented by a signed access token. The
/// database lookup keeps legacy tokens compatible while refusing stale users.
async fn resolve_delegated_principal(
    db: &sqlx::PgPool,
    claims: &Claims,
) -> Result<Principal, AuthError> {
    if claims.token_type != "access" || claims.principal_type.as_deref() != Some("user") {
        return Err(AuthError::Forbidden);
    }
    let user_id = claims.uid.as_deref().ok_or(AuthError::InvalidToken)?;
    let principal = match claims.principal_id.as_deref() {
        Some(principal_id) => crate::db::get_principal_by_id(db, principal_id)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to resolve principal".to_string()))?,
        None => crate::db::get_principal_by_ref(db, "user", user_id)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to resolve principal".to_string()))?,
    }
    .ok_or(AuthError::InvalidToken)?;
    if principal.principal_type != "user" || principal.ref_id != user_id || !principal.active {
        return Err(AuthError::Forbidden);
    }
    let user = crate::db::user::get_user_by_id(db, user_id)
        .await
        .map_err(|_| AuthError::DatabaseError("Failed to resolve user".to_string()))?
        .filter(|user| {
            user.active
                && matches!(
                    user.user_class.as_str(),
                    USER_CLASS_INTERNAL_EMPLOYEE | USER_CLASS_EXTERNAL_CUSTOMER
                )
        })
        .ok_or(AuthError::Forbidden)?;
    if user.id != principal.ref_id {
        return Err(AuthError::Forbidden);
    }
    Ok(principal)
}

fn require_active_organization_context(
    claims: &Claims,
    organization_id: &str,
) -> Result<(), AuthError> {
    if claims.organization_id.as_deref() == Some(organization_id) {
        Ok(())
    } else {
        Err(AuthError::Forbidden)
    }
}

/// Rechecks the live manager membership after matching the signed context.
pub(crate) async fn require_delegated_manager(
    state: &AppState,
    claims: &Claims,
    organization_id: &str,
) -> Result<Principal, AuthError> {
    let db = require_organization_db(state)?;
    require_active_organization_context(claims, organization_id)?;
    let principal = resolve_delegated_principal(db, claims).await?;
    crate::db::require_organization_manager(db, organization_id, &principal.id)
        .await
        .map_err(map_delegated_error)?;
    Ok(principal)
}

pub(crate) async fn require_delegated_mfa(
    state: &AppState,
    claims: &Claims,
) -> Result<(), AuthError> {
    crate::routes::mfa::require_recent_mfa_for_user_claims(state, claims)
        .await
        .map_err(|_| AuthError::Forbidden)
}

/// Preserves a successful lifecycle change when audit persistence is temporarily unavailable.
///
/// This follows the existing administrative audit convention: the request result
/// remains idempotent, while the failure is visible to operators through logs.
async fn audit_organization_event(
    db: &sqlx::PgPool,
    event_type: &str,
    actor: Option<&str>,
    detail: String,
) {
    if let Err(error) = crate::db::create_audit_log(db, event_type, actor, Some(&detail)).await {
        tracing::warn!(event_type, error = %error, "Failed to write organization audit log");
    }
}

async fn list_organizations_handler(
    State(state): State<AppState>,
    Query(query): Query<OrganizationListQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = require_organization_db(&state)?;
    let organizations = crate::db::list_organizations(
        db,
        query.status.as_deref(),
        query.limit.unwrap_or(50),
        query.offset.unwrap_or(0),
    )
    .await
    .map_err(map_organization_error)?;

    Ok(Json(json!({
        "success": true,
        "data": organizations,
    })))
}

async fn create_organization_handler(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<CreateOrganizationRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = require_organization_db(&state)?;
    let organization =
        crate::db::create_organization(db, &payload.slug, &payload.name, &payload.kind)
            .await
            .map_err(map_organization_error)?;
    audit_organization_event(
        db,
        "organization.created",
        Some(&claims.sub),
        format!(
            "organization_id={}, slug={}, kind={}",
            organization.id, organization.slug, organization.kind
        ),
    )
    .await;

    Ok(Json(json!({
        "success": true,
        "data": organization,
    })))
}

async fn get_organization_handler(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = require_organization_db(&state)?;
    let organization = crate::db::get_organization_by_id(db, &organization_id)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?
        .ok_or(AuthError::NotFound)?;

    Ok(Json(json!({
        "success": true,
        "data": organization,
    })))
}

async fn update_organization_status_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    Json(payload): Json<UpdateOrganizationStatusRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = require_organization_db(&state)?;
    let status_change = crate::db::set_organization_status(db, &organization_id, &payload.status)
        .await
        .map_err(map_organization_error)?
        .ok_or(AuthError::NotFound)?;
    audit_organization_event(
        db,
        "organization.status_changed",
        Some(&claims.sub),
        format!(
            "organization_id={}, previous_status={}, status={}",
            status_change.organization.id,
            status_change.previous_status,
            status_change.organization.status
        ),
    )
    .await;

    Ok(Json(json!({
        "success": true,
        "data": status_change.organization,
    })))
}

async fn list_memberships_handler(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    Query(query): Query<OrganizationListQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = require_organization_db(&state)?;
    crate::db::get_organization_by_id(db, &organization_id)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?
        .ok_or(AuthError::NotFound)?;
    let memberships = crate::db::list_organization_memberships(
        db,
        &organization_id,
        query.status.as_deref(),
        query.limit.unwrap_or(50),
        query.offset.unwrap_or(0),
    )
    .await
    .map_err(map_organization_error)?;

    Ok(Json(json!({
        "success": true,
        "data": memberships,
    })))
}

async fn get_membership_handler(
    State(state): State<AppState>,
    Path((organization_id, principal_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = require_organization_db(&state)?;
    let membership = crate::db::get_organization_membership(db, &organization_id, &principal_id)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?
        .ok_or(AuthError::NotFound)?;

    Ok(Json(json!({
        "success": true,
        "data": membership,
    })))
}

async fn upsert_membership_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((organization_id, principal_id)): Path<(String, String)>,
    Json(payload): Json<UpsertOrganizationMembershipRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = require_organization_db(&state)?;
    let membership = crate::db::upsert_organization_membership(
        db,
        &organization_id,
        &principal_id,
        &payload.status,
        Some(&claims.sub),
        payload.management_role.as_deref(),
    )
    .await
    .map_err(map_organization_error)?;
    audit_organization_event(
        db,
        "organization.membership_changed",
        Some(&claims.sub),
        format!(
            "organization_id={}, principal_id={}, status={}",
            membership.organization_id, membership.principal_id, membership.status
        ),
    )
    .await;

    Ok(Json(json!({
        "success": true,
        "data": membership,
    })))
}

async fn list_delegated_memberships_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    Query(query): Query<OrganizationListQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    require_delegated_manager(&state, &claims, &organization_id).await?;
    let db = require_organization_db(&state)?;
    let memberships = crate::db::list_organization_memberships(
        db,
        &organization_id,
        query.status.as_deref(),
        query.limit.unwrap_or(50),
        query.offset.unwrap_or(0),
    )
    .await
    .map_err(map_delegated_error)?;

    Ok(Json(json!({"success": true, "data": memberships})))
}

async fn invite_delegated_member_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    Json(payload): Json<InviteOrganizationMemberRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let actor = require_delegated_manager(&state, &claims, &organization_id).await?;
    require_delegated_mfa(&state, &claims).await?;
    let db = require_organization_db(&state)?;
    let membership = crate::db::invite_organization_member_as_manager(
        db,
        &organization_id,
        &actor.id,
        &payload.principal_id,
        payload.management_role.as_deref(),
    )
    .await
    .map_err(map_delegated_error)?;
    audit_organization_event(
        db,
        "organization.membership.invited",
        Some(&claims.sub),
        format!(
            "organization_id={}, principal_id={}, management_role={}",
            membership.organization_id, membership.principal_id, membership.management_role
        ),
    )
    .await;

    Ok(Json(json!({"success": true, "data": membership})))
}

async fn update_delegated_membership_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((organization_id, principal_id)): Path<(String, String)>,
    Json(payload): Json<UpdateOrganizationMembershipRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let actor = require_delegated_manager(&state, &claims, &organization_id).await?;
    require_delegated_mfa(&state, &claims).await?;
    let db = require_organization_db(&state)?;
    let membership = crate::db::update_organization_membership_as_manager(
        db,
        &organization_id,
        &actor.id,
        &principal_id,
        &payload.status,
        payload.management_role.as_deref(),
    )
    .await
    .map_err(map_delegated_error)?;
    audit_organization_event(
        db,
        "organization.membership.updated",
        Some(&claims.sub),
        format!(
            "organization_id={}, principal_id={}, status={}, management_role={}",
            membership.organization_id,
            membership.principal_id,
            membership.status,
            membership.management_role
        ),
    )
    .await;

    Ok(Json(json!({"success": true, "data": membership})))
}

async fn join_delegated_membership_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((organization_id, target_principal_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = require_organization_db(&state)?;
    let principal = resolve_delegated_principal(db, &claims).await?;
    if principal.id != target_principal_id {
        return Err(AuthError::Forbidden);
    }
    if let Some(context_organization_id) = claims.organization_id.as_deref() {
        if context_organization_id != organization_id {
            return Err(AuthError::Forbidden);
        }
    }
    require_delegated_mfa(&state, &claims).await?;
    let membership = crate::db::join_organization_membership(db, &organization_id, &principal.id)
        .await
        .map_err(map_delegated_error)?;
    audit_organization_event(
        db,
        "organization.membership.joined",
        Some(&claims.sub),
        format!(
            "organization_id={}, principal_id={}",
            membership.organization_id, membership.principal_id
        ),
    )
    .await;

    Ok(Json(json!({"success": true, "data": membership})))
}

async fn list_delegated_roles_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((organization_id, principal_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AuthError> {
    require_delegated_manager(&state, &claims, &organization_id).await?;
    let db = require_organization_db(&state)?;
    let bindings = crate::db::get_organization_role_bindings(db, &organization_id, &principal_id)
        .await
        .map_err(map_delegated_error)?;
    Ok(Json(json!({"success": true, "data": bindings})))
}

async fn assign_delegated_role_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((organization_id, principal_id)): Path<(String, String)>,
    Json(payload): Json<OrganizationRoleBindingRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let actor = require_delegated_manager(&state, &claims, &organization_id).await?;
    require_delegated_mfa(&state, &claims).await?;
    let db = require_organization_db(&state)?;
    let binding = crate::db::assign_organization_role_as_manager(
        db,
        &organization_id,
        &actor.id,
        &principal_id,
        &payload.role_id,
    )
    .await
    .map_err(map_delegated_error)?;
    audit_organization_event(
        db,
        "organization.role_binding.assigned",
        Some(&claims.sub),
        format!(
            "organization_id={}, principal_id={}, role_id={}",
            binding.organization_id, binding.principal_id, binding.role_id
        ),
    )
    .await;
    Ok(Json(json!({"success": true, "data": binding})))
}

async fn revoke_delegated_role_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((organization_id, principal_id, role_id)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let actor = require_delegated_manager(&state, &claims, &organization_id).await?;
    require_delegated_mfa(&state, &claims).await?;
    let db = require_organization_db(&state)?;
    let revoked = crate::db::revoke_organization_role_as_manager(
        db,
        &organization_id,
        &actor.id,
        &principal_id,
        &role_id,
    )
    .await
    .map_err(map_delegated_error)?;
    audit_organization_event(
        db,
        "organization.role_binding.revoked",
        Some(&claims.sub),
        format!(
            "organization_id={}, principal_id={}, role_id={}, revoked={revoked}",
            organization_id, principal_id, role_id
        ),
    )
    .await;
    Ok(Json(json!({"success": true, "data": {"revoked": revoked}})))
}

/// Lists only the service clients whose persisted scope is the caller's organization.
async fn list_delegated_services_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    Query(query): Query<OrganizationServiceListQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    require_delegated_manager(&state, &claims, &organization_id).await?;
    let db = require_organization_db(&state)?;
    let services = svc_db::list_service_clients_in_organization_paginated(
        db,
        &organization_id,
        query.limit.unwrap_or(50).clamp(1, 200),
        query.offset.unwrap_or(0).max(0),
    )
    .await
    .map_err(|error| AuthError::DatabaseError(error.to_string()))?;

    Ok(Json(json!({"success": true, "data": services})))
}

#[derive(Debug, Deserialize)]
struct OrganizationServiceListQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}

/// Creates an organization-scoped service without accepting a caller-selected tenant id.
async fn register_delegated_service_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    Json(payload): Json<RegisterOrganizationServiceRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let actor = require_delegated_manager(&state, &claims, &organization_id).await?;
    require_delegated_mfa(&state, &claims).await?;
    if payload.service_id.trim().is_empty()
        || payload.service_secret.trim().is_empty()
        || payload.name.trim().is_empty()
    {
        return Err(AuthError::MissingCredentials);
    }
    if payload
        .token_ttl_seconds
        .is_some_and(|ttl| ttl <= 0 || ttl > state.config.refresh_token_expiry_seconds)
    {
        return Err(AuthError::InvalidRequest(format!(
            "token_ttl_seconds must be between 1 and {}",
            state.config.refresh_token_expiry_seconds
        )));
    }
    let allowed_scopes = normalize_service_values("allowed_scopes", payload.allowed_scopes, false)?;
    let allowed_audiences =
        normalize_service_values("allowed_audiences", payload.allowed_audiences, true)?;
    let integration_type = defaulted_service_value(payload.integration_type.as_deref(), "internal");
    let owner = payload.owner.as_deref().and_then(trimmed_service_value);
    let contact = payload.contact.as_deref().and_then(trimmed_service_value);
    let db = require_organization_db(&state)?;

    svc_db::create_service_client_as_organization_manager(
        db,
        &organization_id,
        &actor.id,
        svc_db::CreateServiceClientParams {
            service_id: payload.service_id.trim(),
            service_secret: payload.service_secret.trim(),
            name: payload.name.trim(),
            description: payload.description.as_deref(),
            organization_id: Some(&organization_id),
            allowed_scopes: &allowed_scopes,
            allowed_audiences: &allowed_audiences,
            integration_type: &integration_type,
            // Organization-scoped services cannot use introspection endpoints.
            introspection_allowed: false,
            token_ttl_seconds: payload.token_ttl_seconds,
            owner: owner.as_deref(),
            contact: contact.as_deref(),
        },
    )
    .await
    .map_err(|error| {
        if is_unique_violation(error.as_ref()) {
            AuthError::Conflict("Service client already exists".to_string())
        } else if error
            .to_string()
            .contains("organization_service_client_context_inactive")
        {
            AuthError::Forbidden
        } else {
            map_delegated_error(error)
        }
    })?;

    let service =
        svc_db::get_service_client_in_organization(db, &organization_id, payload.service_id.trim())
            .await
            .map_err(|error| AuthError::DatabaseError(error.to_string()))?
            .ok_or(AuthError::Forbidden)?;
    audit_organization_event(
        db,
        "organization.service.created",
        Some(&claims.sub),
        format!(
            "organization_id={}, service_id={}, actor_principal_id={}",
            organization_id, service.service_id, actor.id
        ),
    )
    .await;

    Ok(Json(json!({"success": true, "data": service})))
}

/// Reads a service only after matching both the signed tenant context and stored scope.
async fn get_delegated_service_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((organization_id, service_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AuthError> {
    require_delegated_manager(&state, &claims, &organization_id).await?;
    let db = require_organization_db(&state)?;
    let service = svc_db::get_service_client_in_organization(db, &organization_id, &service_id)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?
        .ok_or(AuthError::NotFound)?;

    Ok(Json(json!({"success": true, "data": service})))
}

/// Updates mutable tenant-service metadata while preserving its fixed scope.
async fn update_delegated_service_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((organization_id, service_id)): Path<(String, String)>,
    Json(payload): Json<UpdateOrganizationServiceRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let actor = require_delegated_manager(&state, &claims, &organization_id).await?;
    require_delegated_mfa(&state, &claims).await?;
    if payload
        .token_ttl_seconds
        .is_some_and(|ttl| ttl <= 0 || ttl > state.config.refresh_token_expiry_seconds)
    {
        return Err(AuthError::InvalidRequest(format!(
            "token_ttl_seconds must be between 1 and {}",
            state.config.refresh_token_expiry_seconds
        )));
    }
    let allowed_scopes = payload
        .allowed_scopes
        .map(|values| normalize_service_values("allowed_scopes", values, false))
        .transpose()?;
    let allowed_audiences = payload
        .allowed_audiences
        .map(|values| normalize_service_values("allowed_audiences", values, true))
        .transpose()?;
    let integration_type = payload
        .integration_type
        .as_deref()
        .and_then(trimmed_service_value);
    let owner = payload.owner.as_deref().and_then(trimmed_service_value);
    let contact = payload.contact.as_deref().and_then(trimmed_service_value);
    let db = require_organization_db(&state)?;
    let updated = svc_db::update_service_client_as_organization_manager(
        db,
        &organization_id,
        &actor.id,
        svc_db::UpdateServiceClientParams {
            service_id: &service_id,
            name: payload.name.as_deref(),
            description: payload.description.as_deref(),
            allowed_scopes: allowed_scopes.as_deref(),
            allowed_audiences: allowed_audiences.as_deref(),
            active: payload.active,
            integration_type: integration_type.as_deref(),
            // The delegated request type cannot enable organization introspection.
            introspection_allowed: Some(false),
            token_ttl_seconds: payload.token_ttl_seconds,
            owner: owner.as_deref(),
            contact: contact.as_deref(),
        },
    )
    .await
    .map_err(map_delegated_error)?;
    if !updated {
        return Err(AuthError::NotFound);
    }
    audit_organization_event(
        db,
        "organization.service.updated",
        Some(&claims.sub),
        format!(
            "organization_id={}, service_id={}, actor_principal_id={}",
            organization_id, service_id, actor.id
        ),
    )
    .await;

    Ok(Json(json!({"success": true, "data": {"updated": true}})))
}

/// Rotates a tenant service secret after live manager and MFA checks.
async fn rotate_delegated_service_secret_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((organization_id, service_id)): Path<(String, String)>,
    Json(payload): Json<RotateServiceSecretRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let actor = require_delegated_manager(&state, &claims, &organization_id).await?;
    require_delegated_mfa(&state, &claims).await?;
    let provided_secret = payload
        .new_secret
        .as_deref()
        .and_then(trimmed_service_value);
    let secret_generated = provided_secret.is_none();
    let new_secret = provided_secret.unwrap_or_else(svc_db::generate_service_secret);
    let db = require_organization_db(&state)?;
    let rotated = svc_db::rotate_service_secret_as_organization_manager(
        db,
        &organization_id,
        &actor.id,
        &service_id,
        &new_secret,
    )
    .await
    .map_err(map_delegated_error)?;
    if !rotated {
        return Err(AuthError::NotFound);
    }
    audit_organization_event(
        db,
        "organization.service.secret_rotated",
        Some(&claims.sub),
        format!(
            "organization_id={}, service_id={}, actor_principal_id={}, generated={secret_generated}",
            organization_id, service_id, actor.id
        ),
    )
    .await;

    let mut data = json!({
        "service_id": service_id,
        "secret_generated": secret_generated,
    });
    if secret_generated {
        data["new_secret"] = json!(new_secret);
    }
    Ok(Json(json!({"success": true, "data": data})))
}

/// Normalizes service scope and audience fields before they reach persistence.
fn normalize_service_values(
    field_name: &str,
    values: Vec<String>,
    allow_wildcard: bool,
) -> Result<Vec<String>, AuthError> {
    let mut normalized = BTreeSet::new();
    for value in values {
        let item = value.trim();
        if item.is_empty() {
            return Err(AuthError::InvalidRequest(format!(
                "{field_name} must not contain empty values"
            )));
        }
        if item.split_whitespace().count() != 1 {
            return Err(AuthError::InvalidRequest(format!(
                "{field_name} values must not contain whitespace"
            )));
        }
        if item == "*" && !allow_wildcard {
            return Err(AuthError::InvalidRequest(format!(
                "{field_name} does not allow wildcard values"
            )));
        }
        normalized.insert(item.to_string());
    }
    if normalized.is_empty() {
        return Err(AuthError::InvalidRequest(format!(
            "{field_name} must contain at least one value"
        )));
    }
    Ok(normalized.into_iter().collect())
}

fn trimmed_service_value(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn defaulted_service_value(value: Option<&str>, default: &str) -> String {
    value
        .and_then(trimmed_service_value)
        .unwrap_or_else(|| default.to_string())
}

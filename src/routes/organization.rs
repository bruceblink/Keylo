use axum::{
    extract::{Path, Query, State},
    response::Json,
    routing::{get, put},
    Router,
};
use serde_json::json;

use crate::{
    errors::{is_unique_violation, AuthError},
    models::{
        Claims, CreateOrganizationRequest, OrganizationListQuery, UpdateOrganizationStatusRequest,
        UpsertOrganizationMembershipRequest,
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
        | "invalid_organization_membership_status" => AuthError::InvalidRequest(message),
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

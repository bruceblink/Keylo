use axum::{
    extract::{Path, Query, State},
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde_json::json;
use std::collections::HashMap;

use crate::{
    errors::AuthError,
    models::{
        AssignResourcePermissionRequest, Claims, CreateResourceRequest, ResourceListQuery,
        RevertResourceChangeRequest, RevokeResourcePermissionRequest, UpdateResourceRequest,
    },
    state::AppState,
};

pub fn resource_admin_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/admin/resources", get(list_resources_handler))
        .route("/v1/admin/resources", post(create_resource_handler))
        .route(
            "/v1/admin/resources/{resource_id}",
            put(update_resource_handler),
        )
        .route(
            "/v1/admin/resources/{resource_id}/changes",
            get(list_resource_changes_handler),
        )
        .route(
            "/v1/admin/resources/{resource_id}/changes/{version}/revert",
            post(revert_resource_change_handler),
        )
        .route(
            "/v1/admin/resources/{resource_id}/permissions",
            get(get_resource_permissions_handler),
        )
        .route(
            "/v1/admin/resources/{resource_id}/permissions",
            post(assign_resource_permission_handler),
        )
        .route(
            "/v1/admin/resources/{resource_id}/permissions/{permission_id}",
            delete(revoke_resource_permission_handler),
        )
}

async fn list_resources_handler(
    State(state): State<AppState>,
    Query(query): Query<ResourceListQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let resources = crate::db::list_resources(
        db,
        query.app.as_deref(),
        query.resource_type.as_deref(),
        query.active,
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "data": resources
    })))
}

async fn create_resource_handler(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<CreateResourceRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    if payload.app.trim().is_empty()
        || payload.resource_type.trim().is_empty()
        || payload.code.trim().is_empty()
        || payload.name.trim().is_empty()
    {
        return Err(AuthError::MissingCredentials);
    }

    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let permission_ids = payload.permission_ids.unwrap_or_default();
    let resource = crate::db::create_resource(
        db,
        crate::db::CreateResourceParams {
            app: payload.app.trim(),
            resource_type: payload.resource_type.trim(),
            code: payload.code.trim(),
            name: payload.name.trim(),
            parent_id: payload.parent_id.as_deref(),
            display_order: payload.display_order.unwrap_or(0),
            description: payload.description.as_deref(),
            metadata: payload.metadata.as_ref(),
            permission_ids: &permission_ids,
        },
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    crate::db::create_audit_log(
        db,
        "resource.created",
        Some(&claims.sub),
        Some(&format!(
            "resource_id={}, app={}, type={}, code={}",
            resource.id, resource.app, resource.resource_type, resource.code
        )),
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "data": resource
    })))
}

async fn get_resource_permissions_handler(
    State(state): State<AppState>,
    Path(resource_id): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let permissions = crate::db::get_resource_permissions(db, &resource_id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "data": permissions
    })))
}

async fn update_resource_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(resource_id): Path<String>,
    Json(payload): Json<UpdateResourceRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let before = crate::db::get_resource_by_id(db, &resource_id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        .ok_or(AuthError::NotFound)?;
    let resource = crate::db::update_resource(
        db,
        &resource_id,
        crate::db::UpdateResourceParams {
            name: payload.name.as_deref(),
            display_order: payload.display_order,
            description: payload.description.as_deref(),
            metadata: payload.metadata.as_ref(),
            active: payload.active,
            expected_version: payload.expected_version,
        },
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?
    .ok_or_else(|| {
        AuthError::Conflict("Resource changed since the supplied expected_version".to_string())
    })?;
    let change_reason = payload
        .change_reason
        .as_deref()
        .map(str::trim)
        .filter(|reason| !reason.is_empty());
    crate::db::create_resource_change_history(
        db,
        Some(&claims.sub),
        change_reason,
        &before,
        &resource,
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    crate::db::create_audit_log(
        db,
        "resource.updated",
        Some(&claims.sub),
        Some(&format!(
            "resource_id={}, version={}{}",
            resource.id,
            resource.version,
            audit_reason_suffix(change_reason),
        )),
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "data": resource
    })))
}

async fn list_resource_changes_handler(
    State(state): State<AppState>,
    Path(resource_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let limit = params
        .get("limit")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    let offset = params
        .get("offset")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0)
        .max(0);
    let changes = crate::db::list_resource_change_history(db, &resource_id, limit, offset)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "data": changes
    })))
}

async fn revert_resource_change_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((resource_id, history_version)): Path<(String, i64)>,
    Json(payload): Json<RevertResourceChangeRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let change_reason = payload.change_reason.trim();
    if change_reason.is_empty() {
        return Err(AuthError::InvalidRequest(
            "change_reason is required when reverting a resource change".to_string(),
        ));
    }

    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let before = crate::db::get_resource_by_id(db, &resource_id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        .ok_or(AuthError::NotFound)?;
    let historical_change =
        crate::db::get_resource_change_history(db, &resource_id, history_version)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?
            .ok_or(AuthError::NotFound)?;
    let target: crate::models::Resource = serde_json::from_value(historical_change.before_state)
        .map_err(|e| {
            AuthError::InternalServerError(format!("Stored resource history is invalid: {e}"))
        })?;
    let resource = crate::db::restore_resource(db, &resource_id, &target, payload.expected_version)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        .ok_or_else(|| {
            AuthError::Conflict("Resource changed since the supplied expected_version".to_string())
        })?;
    crate::db::create_resource_change_history(
        db,
        Some(&claims.sub),
        Some(change_reason),
        &before,
        &resource,
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    crate::db::create_audit_log(
        db,
        "resource.reverted",
        Some(&claims.sub),
        Some(&format!(
            "resource_id={}, reverted_change_version={}, version={}, reason={}",
            resource.id, history_version, resource.version, change_reason
        )),
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "data": resource
    })))
}

async fn assign_resource_permission_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(resource_id): Path<String>,
    Json(payload): Json<AssignResourcePermissionRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    crate::db::assign_permission_to_resource(db, &resource_id, &payload.permission_id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    crate::db::create_audit_log(
        db,
        "resource.permission_assigned",
        Some(&claims.sub),
        Some(&format!(
            "resource_id={}, permission_id={}{}",
            resource_id,
            payload.permission_id,
            audit_reason_suffix(payload.change_reason.as_deref()),
        )),
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "message": "Permission assigned to resource successfully"
    })))
}

/// Formats an optional operator reason for audit data without storing blank values.
fn audit_reason_suffix(change_reason: Option<&str>) -> String {
    change_reason
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .map(|reason| format!(", reason={reason}"))
        .unwrap_or_default()
}

async fn revoke_resource_permission_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((resource_id, permission_id)): Path<(String, String)>,
    Json(payload): Json<RevokeResourcePermissionRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let revoked = crate::db::revoke_permission_from_resource(db, &resource_id, &permission_id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    if !revoked {
        return Err(AuthError::NotFound);
    }
    crate::db::create_audit_log(
        db,
        "resource.permission_revoked",
        Some(&claims.sub),
        Some(&format!(
            "resource_id={}, permission_id={}{}",
            resource_id,
            permission_id,
            audit_reason_suffix(payload.change_reason.as_deref()),
        )),
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "message": "Permission revoked from resource successfully"
    })))
}

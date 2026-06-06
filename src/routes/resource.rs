use axum::{
    extract::{Path, Query, State},
    response::Json,
    routing::{get, post},
    Router,
};
use serde_json::json;

use crate::{
    errors::AuthError,
    models::{AssignResourcePermissionRequest, Claims, CreateResourceRequest, ResourceListQuery},
    state::AppState,
};

pub fn resource_admin_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/admin/resources", get(list_resources_handler))
        .route("/v1/admin/resources", post(create_resource_handler))
        .route(
            "/v1/admin/resources/{resource_id}/permissions",
            get(get_resource_permissions_handler),
        )
        .route(
            "/v1/admin/resources/{resource_id}/permissions",
            post(assign_resource_permission_handler),
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
            "resource_id={}, permission_id={}",
            resource_id, payload.permission_id
        )),
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "message": "Permission assigned to resource successfully"
    })))
}

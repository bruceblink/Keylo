use axum::{
    extract::{Path, Query, State},
    response::Json,
    routing::{delete, get, post},
    Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    errors::AuthError,
    models::{
        AssignRoleRequest, Claims, PrincipalEffectivePermissionsResponse, PrincipalListQuery,
    },
    state::AppState,
};

pub fn principal_admin_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/admin/principals", get(list_principals_handler))
        .route(
            "/v1/admin/refresh-sessions",
            get(list_refresh_sessions_handler),
        )
        .route(
            "/v1/admin/refresh-sessions/{session_id}",
            delete(revoke_refresh_session_handler),
        )
        .route(
            "/v1/admin/principals/{principal_id}",
            get(get_principal_handler),
        )
        .route(
            "/v1/admin/principals/{principal_id}/roles",
            get(get_principal_roles_handler),
        )
        .route(
            "/v1/admin/principals/{principal_id}/roles",
            post(assign_principal_role_handler),
        )
        .route(
            "/v1/admin/principals/{principal_id}/roles/{role_id}",
            delete(revoke_principal_role_handler),
        )
        .route(
            "/v1/admin/principals/{principal_id}/effective-permissions",
            get(get_principal_effective_permissions_handler),
        )
        .route(
            "/v1/admin/principals/{principal_id}/refresh-sessions",
            get(list_principal_refresh_sessions_handler),
        )
        .route(
            "/v1/admin/principals/{principal_id}/refresh-sessions",
            delete(revoke_principal_refresh_sessions_handler),
        )
        .route(
            "/v1/admin/principals/{principal_id}/refresh-sessions/{session_id}",
            delete(revoke_principal_refresh_session_handler),
        )
}

#[derive(Debug, Deserialize)]
struct RefreshSessionListQuery {
    include_revoked: Option<bool>,
    principal_id: Option<String>,
    client_id: Option<String>,
    login_ip: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn list_principals_handler(
    State(state): State<AppState>,
    Query(query): Query<PrincipalListQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let principals = crate::db::list_principals(
        db,
        query.principal_type.as_deref(),
        query.active,
        query.limit.unwrap_or(50).clamp(1, 200),
        query.offset.unwrap_or(0).max(0),
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "data": principals
    })))
}

async fn list_refresh_sessions_handler(
    State(state): State<AppState>,
    Query(query): Query<RefreshSessionListQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let sessions = crate::db::list_refresh_sessions(
        db,
        query.include_revoked.unwrap_or(false),
        query.principal_id.as_deref(),
        query.client_id.as_deref(),
        query.login_ip.as_deref(),
        query.limit.unwrap_or(50).clamp(1, 200),
        query.offset.unwrap_or(0).max(0),
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "data": sessions
    })))
}

async fn revoke_refresh_session_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let revoked = crate::db::revoke_refresh_session(db, &session_id, Some("admin_revoked"))
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    if !revoked {
        return Err(AuthError::NotFound);
    }
    crate::db::create_audit_log(
        db,
        "refresh_session.revoked",
        Some(&claims.sub),
        Some(&format!("session_id={}", session_id)),
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "message": "Refresh session revoked successfully"
    })))
}

async fn get_principal_handler(
    State(state): State<AppState>,
    Path(principal_id): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let principal = crate::db::get_principal_by_id(db, &principal_id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        .ok_or(AuthError::NotFound)?;

    Ok(Json(json!({
        "success": true,
        "data": principal
    })))
}

async fn get_principal_roles_handler(
    State(state): State<AppState>,
    Path(principal_id): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let roles = crate::db::get_principal_roles(db, &principal_id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "data": roles
    })))
}

async fn assign_principal_role_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(principal_id): Path<String>,
    Json(payload): Json<AssignRoleRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    crate::db::assign_role_to_principal(db, &principal_id, &payload.role_id)
        .await
        .map_err(|e| AuthError::InvalidRequest(e.to_string()))?;
    crate::db::create_audit_log(
        db,
        "principal.role_assigned",
        Some(&claims.sub),
        Some(&format!(
            "principal_id={}, role_id={}",
            principal_id, payload.role_id
        )),
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "message": "Role assigned to principal successfully"
    })))
}

async fn revoke_principal_role_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((principal_id, role_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let revoked = crate::db::revoke_role_from_principal(db, &principal_id, &role_id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    if !revoked {
        return Err(AuthError::NotFound);
    }
    crate::db::create_audit_log(
        db,
        "principal.role_revoked",
        Some(&claims.sub),
        Some(&format!(
            "principal_id={}, role_id={}",
            principal_id, role_id
        )),
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "message": "Role revoked from principal successfully"
    })))
}

async fn get_principal_effective_permissions_handler(
    State(state): State<AppState>,
    Path(principal_id): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let principal = crate::db::get_principal_by_id(db, &principal_id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        .ok_or(AuthError::NotFound)?;
    let roles = crate::db::get_principal_roles(db, &principal.id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    let permissions = crate::db::get_principal_permissions(db, &principal.id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "data": PrincipalEffectivePermissionsResponse {
            principal,
            roles,
            permissions,
        }
    })))
}

async fn list_principal_refresh_sessions_handler(
    State(state): State<AppState>,
    Path(principal_id): Path<String>,
    Query(query): Query<RefreshSessionListQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    if crate::db::get_principal_by_id(db, &principal_id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        .is_none()
    {
        return Err(AuthError::NotFound);
    }

    let sessions = crate::db::list_refresh_sessions_for_principal(
        db,
        &principal_id,
        query.include_revoked.unwrap_or(false),
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "data": sessions
    })))
}

async fn revoke_principal_refresh_sessions_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(principal_id): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let revoked =
        crate::db::revoke_principal_refresh_sessions(db, &principal_id, Some("admin_revoked"))
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    crate::db::create_audit_log(
        db,
        "principal.refresh_sessions_revoked",
        Some(&claims.sub),
        Some(&format!(
            "principal_id={}, revoked={}",
            principal_id, revoked
        )),
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "revoked": revoked
    })))
}

async fn revoke_principal_refresh_session_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path((principal_id, session_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let sessions = crate::db::list_refresh_sessions_for_principal(db, &principal_id, true)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    if !sessions.iter().any(|session| session.id == session_id) {
        return Err(AuthError::NotFound);
    }
    let revoked = crate::db::revoke_refresh_session(db, &session_id, Some("admin_revoked"))
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    if !revoked {
        return Err(AuthError::NotFound);
    }
    crate::db::create_audit_log(
        db,
        "principal.refresh_session_revoked",
        Some(&claims.sub),
        Some(&format!(
            "principal_id={}, session_id={}",
            principal_id, session_id
        )),
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "message": "Refresh session revoked successfully"
    })))
}

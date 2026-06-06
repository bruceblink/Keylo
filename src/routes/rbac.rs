use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde_json::json;
use std::collections::HashMap;

use crate::{
    db::*,
    errors::is_unique_violation,
    models::{Claims, *},
    state::AppState,
    utils::{require_db, ApiResponse},
};

/// 创建RBAC路由
pub fn rbac_routes() -> Router<AppState> {
    Router::new()
        // 角色管理路由
        .route("/roles", get(get_roles))
        .route("/roles", post(create_role_handler))
        .route("/roles/{role_id}", get(get_role))
        .route("/roles/{role_id}", put(update_role_handler))
        .route("/roles/{role_id}", delete(delete_role_handler))
        // 权限管理路由
        .route("/permissions", get(get_permissions))
        .route("/permissions", post(create_permission_handler))
        .route("/permissions/{permission_id}", get(get_permission))
        .route(
            "/permissions/{permission_id}",
            put(update_permission_handler),
        )
        .route(
            "/permissions/{permission_id}",
            delete(delete_permission_handler),
        )
        // 用户角色管理路由
        .route("/users/{user_id}/roles", get(get_user_roles_handler))
        .route("/users/{user_id}/roles", post(assign_role_to_user_handler))
        .route(
            "/users/{user_id}/roles/batch",
            post(assign_roles_to_user_batch_handler),
        )
        .route(
            "/users/{user_id}/roles/{role_id}",
            delete(revoke_role_from_user_handler),
        )
        // 角色权限管理路由
        .route(
            "/roles/{role_id}/permissions",
            get(get_role_permissions_handler),
        )
        .route(
            "/roles/{role_id}/permissions",
            post(assign_permission_to_role_handler),
        )
        .route(
            "/roles/{role_id}/permissions/batch",
            post(assign_permissions_to_role_batch_handler),
        )
        .route(
            "/roles/{role_id}/permissions/{permission_id}",
            delete(revoke_permission_from_role_handler),
        )
        // 用户权限查询路由
        .route(
            "/users/{user_id}/permissions",
            get(get_user_permissions_handler),
        )
        .route(
            "/users/{user_id}/check-permission/{permission_name}",
            get(check_user_permission),
        )
}

async fn audit_event(state: &AppState, event_type: &str, actor: Option<&str>, detail: String) {
    if let Some(db) = &state.db {
        if let Err(err) = create_audit_log(db, event_type, actor, Some(&detail)).await {
            tracing::warn!("Failed to write RBAC audit log: {}", err);
        }
    }
}

fn error_response(
    status: StatusCode,
    error: &str,
    message: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(json!({
            "success": false,
            "error": error,
            "message": message
        })),
    )
}

fn invalid_assignable_to_response() -> (StatusCode, Json<serde_json::Value>) {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_assignable_to",
        "assignable_to must be one of: user, service, client, all",
    )
}

fn role_assignment_error_response(err: &anyhow::Error) -> (StatusCode, Json<serde_json::Value>) {
    let message = err.to_string();
    if message.starts_with("role_not_assignable_to_principal_type")
        || message.starts_with("invalid_role_assignable_to")
    {
        return error_response(StatusCode::BAD_REQUEST, "invalid_role_assignment", &message);
    }

    if message == "role_not_found" {
        return error_response(StatusCode::NOT_FOUND, "role_not_found", "Role not found");
    }

    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "role_assignment_failed",
        &format!("Failed to assign role to user: {}", err),
    )
}

fn role_update_error_response(err: &anyhow::Error) -> (StatusCode, Json<serde_json::Value>) {
    let message = err.to_string();
    if message.starts_with("role_assignable_to_conflicts_with_existing_assignments") {
        return error_response(StatusCode::CONFLICT, "role_assignment_conflict", &message);
    }

    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "role_update_failed",
        &format!("Failed to update role: {}", err),
    )
}

/// 获取所有角色
async fn get_roles(State(state): State<AppState>) -> ApiResponse {
    match get_all_roles(require_db(&state)?).await {
        Ok(roles) => Ok(Json(json!({
            "success": true,
            "data": roles
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to get roles: {}", e)
            })),
        )),
    }
}

/// 创建角色
async fn create_role_handler(
    claims: Claims,
    State(state): State<AppState>,
    Json(req): Json<CreateRoleRequest>,
) -> ApiResponse {
    let assignable_to = req.assignable_to.as_deref().unwrap_or("all");
    if !valid_role_assignable_to(assignable_to) {
        return Err(invalid_assignable_to_response());
    }

    match create_role_with_options(
        require_db(&state)?,
        &req.name,
        req.description.as_deref(),
        assignable_to,
        req.system.unwrap_or(false),
    )
    .await
    {
        Ok(role) => {
            audit_event(
                &state,
                "rbac.role.created",
                Some(&claims.sub),
                format!("role_id={}, role_name={}", role.id, role.name),
            )
            .await;
            Ok(Json(json!({
                "success": true,
                "data": role
            })))
        }
        Err(e) => {
            if is_unique_violation(e.as_ref()) {
                Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "success": false,
                        "error": "Role with this name already exists"
                    })),
                ))
            } else {
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "success": false,
                        "error": format!("Failed to create role: {}", e)
                    })),
                ))
            }
        }
    }
}

/// 获取单个角色
async fn get_role(State(state): State<AppState>, Path(role_id): Path<String>) -> ApiResponse {
    let db = require_db(&state)?;

    match get_role_by_id(db, &role_id).await {
        Ok(Some(role)) => match get_role_permissions(db, &role_id).await {
            Ok(permissions) => Ok(Json(json!({
                "success": true,
                "data": RoleDetail {
                    role,
                    permissions,
                }
            }))),
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Failed to get role permissions: {}", e)
                })),
            )),
        },
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "Role not found"
            })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to get role: {}", e)
            })),
        )),
    }
}

/// 更新角色
async fn update_role_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(role_id): Path<String>,
    Json(req): Json<UpdateRoleRequest>,
) -> ApiResponse {
    if let Some(assignable_to) = req.assignable_to.as_deref() {
        if !valid_role_assignable_to(assignable_to) {
            return Err(invalid_assignable_to_response());
        }
    }

    match update_role(
        require_db(&state)?,
        &role_id,
        req.name.as_deref(),
        req.description.as_deref(),
        req.assignable_to.as_deref(),
        req.system,
    )
    .await
    {
        Ok(Some(role)) => {
            audit_event(
                &state,
                "rbac.role.updated",
                Some(&claims.sub),
                format!("role_id={}, role_name={}", role.id, role.name),
            )
            .await;
            Ok(Json(json!({
                "success": true,
                "data": role
            })))
        }
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "Role not found"
            })),
        )),
        Err(e) => {
            if is_unique_violation(e.as_ref()) {
                Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "success": false,
                        "error": "Role with this name already exists"
                    })),
                ))
            } else {
                Err(role_update_error_response(&e))
            }
        }
    }
}

/// 删除角色
async fn delete_role_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(role_id): Path<String>,
) -> ApiResponse {
    match delete_role(require_db(&state)?, &role_id).await {
        Ok(true) => {
            audit_event(
                &state,
                "rbac.role.deleted",
                Some(&claims.sub),
                format!("role_id={}", role_id),
            )
            .await;
            Ok(Json(json!({
                "success": true,
                "message": "Role deleted successfully"
            })))
        }
        Ok(false) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "Role not found"
            })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to delete role: {}", e)
            })),
        )),
    }
}

/// 获取所有权限
async fn get_permissions(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResponse {
    let db = require_db(&state)?;
    let result = if let Some(prefix) = params.get("prefix") {
        get_permissions_by_prefix(db, prefix).await
    } else {
        get_all_permissions(db).await
    };

    match result {
        Ok(permissions) => Ok(Json(json!({
            "success": true,
            "data": permissions
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to get permissions: {}", e)
            })),
        )),
    }
}

/// 创建权限
async fn create_permission_handler(
    claims: Claims,
    State(state): State<AppState>,
    Json(req): Json<CreatePermissionRequest>,
) -> ApiResponse {
    match create_permission(require_db(&state)?, &req.name, req.description.as_deref()).await {
        Ok(permission) => {
            audit_event(
                &state,
                "rbac.permission.created",
                Some(&claims.sub),
                format!(
                    "permission_id={}, permission_name={}",
                    permission.id, permission.name
                ),
            )
            .await;
            Ok(Json(json!({
                "success": true,
                "data": permission
            })))
        }
        Err(e) => {
            if is_unique_violation(e.as_ref()) {
                Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "success": false,
                        "error": "Permission with this name already exists"
                    })),
                ))
            } else {
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "success": false,
                        "error": format!("Failed to create permission: {}", e)
                    })),
                ))
            }
        }
    }
}

/// 获取单个权限
async fn get_permission(
    State(state): State<AppState>,
    Path(permission_id): Path<String>,
) -> ApiResponse {
    match get_permission_by_id(require_db(&state)?, &permission_id).await {
        Ok(Some(permission)) => Ok(Json(json!({
            "success": true,
            "data": permission
        }))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "Permission not found"
            })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to get permission: {}", e)
            })),
        )),
    }
}

/// 更新权限
async fn update_permission_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(permission_id): Path<String>,
    Json(req): Json<UpdatePermissionRequest>,
) -> ApiResponse {
    match update_permission(
        require_db(&state)?,
        &permission_id,
        req.name.as_deref(),
        req.description.as_deref(),
    )
    .await
    {
        Ok(Some(permission)) => {
            audit_event(
                &state,
                "rbac.permission.updated",
                Some(&claims.sub),
                format!(
                    "permission_id={}, permission_name={}",
                    permission.id, permission.name
                ),
            )
            .await;
            Ok(Json(json!({
                "success": true,
                "data": permission
            })))
        }
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "Permission not found"
            })),
        )),
        Err(e) => {
            if is_unique_violation(e.as_ref()) {
                Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "success": false,
                        "error": "Permission with this name already exists"
                    })),
                ))
            } else {
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "success": false,
                        "error": format!("Failed to update permission: {}", e)
                    })),
                ))
            }
        }
    }
}

/// 删除权限
async fn delete_permission_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(permission_id): Path<String>,
) -> ApiResponse {
    match delete_permission(require_db(&state)?, &permission_id).await {
        Ok(true) => {
            audit_event(
                &state,
                "rbac.permission.deleted",
                Some(&claims.sub),
                format!("permission_id={}", permission_id),
            )
            .await;
            Ok(Json(json!({
                "success": true,
                "message": "Permission deleted successfully"
            })))
        }
        Ok(false) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "Permission not found"
            })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to delete permission: {}", e)
            })),
        )),
    }
}

/// 获取用户的角色
async fn get_user_roles_handler(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> ApiResponse {
    match get_user_roles(require_db(&state)?, &user_id).await {
        Ok(roles) => Ok(Json(json!({
            "success": true,
            "data": roles
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to get user roles: {}", e)
            })),
        )),
    }
}

/// 为用户分配角色
async fn assign_role_to_user_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(req): Json<AssignRoleRequest>,
) -> ApiResponse {
    match assign_role_to_user(require_db(&state)?, &user_id, &req.role_id).await {
        Ok(_) => {
            audit_event(
                &state,
                "rbac.user.role_assigned",
                Some(&claims.sub),
                format!("target_user_id={}, role_id={}", user_id, req.role_id),
            )
            .await;
            Ok(Json(json!({
                "success": true,
                "message": "Role assigned to user successfully"
            })))
        }
        Err(e) => Err(role_assignment_error_response(&e)),
    }
}

/// 撤销用户的角色
async fn revoke_role_from_user_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Path(role_id): Path<String>,
) -> ApiResponse {
    match revoke_role_from_user(require_db(&state)?, &user_id, &role_id).await {
        Ok(true) => {
            audit_event(
                &state,
                "rbac.user.role_revoked",
                Some(&claims.sub),
                format!("target_user_id={}, role_id={}", user_id, role_id),
            )
            .await;
            Ok(Json(json!({
                "success": true,
                "message": "Role revoked from user successfully"
            })))
        }
        Ok(false) => Err(error_response(
            StatusCode::NOT_FOUND,
            "role_not_bound",
            "User role assignment not found",
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to revoke role from user: {}", e)
            })),
        )),
    }
}

/// 获取角色的权限
async fn get_role_permissions_handler(
    State(state): State<AppState>,
    Path(role_id): Path<String>,
) -> ApiResponse {
    match get_role_permissions(require_db(&state)?, &role_id).await {
        Ok(permissions) => Ok(Json(json!({
            "success": true,
            "data": permissions
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to get role permissions: {}", e)
            })),
        )),
    }
}

/// 为角色分配权限
async fn assign_permission_to_role_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(role_id): Path<String>,
    Json(req): Json<AssignPermissionRequest>,
) -> ApiResponse {
    match assign_permission_to_role(require_db(&state)?, &role_id, &req.permission_id).await {
        Ok(_) => {
            audit_event(
                &state,
                "rbac.role.permission_assigned",
                Some(&claims.sub),
                format!("role_id={}, permission_id={}", role_id, req.permission_id),
            )
            .await;
            Ok(Json(json!({
                "success": true,
                "message": "Permission assigned to role successfully"
            })))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to assign permission to role: {}", e)
            })),
        )),
    }
}

/// 撤销角色的权限
async fn revoke_permission_from_role_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(role_id): Path<String>,
    Path(permission_id): Path<String>,
) -> ApiResponse {
    match revoke_permission_from_role(require_db(&state)?, &role_id, &permission_id).await {
        Ok(true) => {
            audit_event(
                &state,
                "rbac.role.permission_revoked",
                Some(&claims.sub),
                format!("role_id={}, permission_id={}", role_id, permission_id),
            )
            .await;
            Ok(Json(json!({
                "success": true,
                "message": "Permission revoked from role successfully"
            })))
        }
        Ok(false) => Err(error_response(
            StatusCode::NOT_FOUND,
            "permission_not_bound",
            "Role permission assignment not found",
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to revoke permission from role: {}", e)
            })),
        )),
    }
}

/// 为用户批量分配角色
async fn assign_roles_to_user_batch_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(req): Json<AssignRolesBatchRequest>,
) -> ApiResponse {
    if req.role_ids.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "role_not_bound",
            "role_ids must not be empty",
        ));
    }

    match assign_roles_to_user_batch(require_db(&state)?, &user_id, &req.role_ids).await {
        Ok(_) => {
            audit_event(
                &state,
                "rbac.user.roles_assigned_batch",
                Some(&claims.sub),
                format!(
                    "target_user_id={}, role_ids={}",
                    user_id,
                    req.role_ids.join(",")
                ),
            )
            .await;
            Ok(Json(json!({
                "success": true,
                "message": "Roles assigned to user successfully"
            })))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to assign roles to user: {}", e)
            })),
        )),
    }
}

/// 为角色批量分配权限
async fn assign_permissions_to_role_batch_handler(
    claims: Claims,
    State(state): State<AppState>,
    Path(role_id): Path<String>,
    Json(req): Json<AssignPermissionsBatchRequest>,
) -> ApiResponse {
    if req.permission_ids.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "permission_not_bound",
            "permission_ids must not be empty",
        ));
    }

    match assign_permissions_to_role_batch(require_db(&state)?, &role_id, &req.permission_ids).await
    {
        Ok(_) => {
            audit_event(
                &state,
                "rbac.role.permissions_assigned_batch",
                Some(&claims.sub),
                format!(
                    "role_id={}, permission_ids={}",
                    role_id,
                    req.permission_ids.join(",")
                ),
            )
            .await;
            Ok(Json(json!({
                "success": true,
                "message": "Permissions assigned to role successfully"
            })))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to assign permissions to role: {}", e)
            })),
        )),
    }
}

/// 获取用户的所有权限
async fn get_user_permissions_handler(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> ApiResponse {
    match get_user_permissions(require_db(&state)?, &user_id).await {
        Ok(permissions) => Ok(Json(json!({
            "success": true,
            "data": permissions
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to get user permissions: {}", e)
            })),
        )),
    }
}

/// 检查用户是否有特定权限
async fn check_user_permission(
    State(state): State<AppState>,
    Path((user_id, permission_name)): Path<(String, String)>,
) -> ApiResponse {
    match user_has_permission(require_db(&state)?, &user_id, &permission_name).await {
        Ok(has_permission) => Ok(Json(json!({
            "success": true,
            "data": {
                "user_id": user_id,
                "permission": permission_name,
                "has_permission": has_permission
            }
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to check user permission: {}", e)
            })),
        )),
    }
}

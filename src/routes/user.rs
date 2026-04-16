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
    handlers::user::import_third_party_users,
    models::{Claims, *},
    state::AppState,
    utils::{require_db, ApiResponse},
};

pub fn user_routes() -> Router<AppState> {
    admin_user_routes().merge(self_user_routes())
}

pub fn admin_user_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/admin/users", get(list_users_handler))
        .route("/v1/admin/users", post(create_user_handler))
        .route("/v1/admin/users/{user_id}", get(get_user_handler))
        .route("/v1/admin/users/{user_id}", put(update_user_handler))
        .route("/v1/admin/users/{user_id}", delete(delete_user_handler))
        .route(
            "/v1/admin/users/migrations/import",
            post(import_third_party_users),
        )
        .route(
            "/v1/admin/users/{user_id}/reset-password",
            post(reset_user_password_handler),
        )
}

pub fn self_user_routes() -> Router<AppState> {
    Router::new().route("/v1/user/change-password", post(change_password_handler))
}

async fn list_users_handler(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResponse {
    let db = require_db(&state)?;
    let limit = params
        .get("limit")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 500);
    let offset = params
        .get("offset")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0)
        .max(0);

    match list_users(db, limit, offset).await {
        Ok(users) => Ok(Json(json!({
            "success": true,
            "data": users,
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to list users: {}", e),
            })),
        )),
    }
}

async fn create_user_handler(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> ApiResponse {
    let db = require_db(&state)?;

    match create_user(db, &req.username, &req.email, req.password.as_deref()).await {
        Ok(user) => Ok(Json(json!({
            "success": true,
            "data": user,
        }))),
        Err(e) => {
            if e.to_string().contains("duplicate key") {
                Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "success": false,
                        "error": "Username or email already exists",
                    })),
                ))
            } else {
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "success": false,
                        "error": format!("Failed to create user: {}", e),
                    })),
                ))
            }
        }
    }
}

async fn get_user_handler(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> ApiResponse {
    let db = require_db(&state)?;

    match crate::db::user::get_user_by_id(db, &user_id).await {
        Ok(Some(user)) => Ok(Json(json!({
            "success": true,
            "data": user,
        }))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "User not found",
            })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to fetch user: {}", e),
            })),
        )),
    }
}

async fn update_user_handler(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> ApiResponse {
    let db = require_db(&state)?;

    match crate::db::user::update_user(
        db,
        &user_id,
        req.username.as_deref(),
        req.email.as_deref(),
        req.password.as_deref(),
        req.active,
    )
    .await
    {
        Ok(Some(user)) => Ok(Json(json!({
            "success": true,
            "data": user,
        }))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "User not found",
            })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to update user: {}", e),
            })),
        )),
    }
}

async fn delete_user_handler(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> ApiResponse {
    let db = require_db(&state)?;

    match crate::db::user::delete_user(db, &user_id).await {
        Ok(true) => Ok(Json(json!({
            "success": true,
            "message": "User deleted successfully",
        }))),
        Ok(false) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "User not found",
            })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to delete user: {}", e),
            })),
        )),
    }
}

async fn reset_user_password_handler(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(req): Json<ResetPasswordRequest>,
) -> ApiResponse {
    let db = require_db(&state)?;

    match crate::db::user::reset_user_password(db, &user_id, &req.password).await {
        Ok(true) => Ok(Json(json!({
            "success": true,
            "message": "Password reset successfully",
        }))),
        Ok(false) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "User not found",
            })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to reset password: {}", e),
            })),
        )),
    }
}

async fn change_password_handler(
    State(state): State<AppState>,
    claims: Claims,
    Json(req): Json<ChangePasswordRequest>,
) -> ApiResponse {
    let db = require_db(&state)?;

    // 从JWT claims中提取用户ID
    // sub字段格式可能是 "user:username" 或 "client:username" 或直接的UUID
    let user_id = if claims.sub.starts_with("user:") {
        // 如果是user格式，从数据库中通过用户名查找用户ID
        let username = &claims.sub[5..]; // 移除"user:"前缀
        tracing::debug!("Looking up user by username: {}", username);
        match crate::db::user::get_user_by_username(db, username).await {
            Ok(Some(user)) => {
                tracing::debug!("Found user: {}", user.id);
                user.id
            }
            Ok(None) => {
                tracing::warn!("User not found for username: {}", username);
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "success": false,
                        "error": "User not found",
                    })),
                ));
            }
            Err(e) => {
                tracing::warn!("Database error: {}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "success": false,
                        "error": format!("Failed to find user: {}", e),
                    })),
                ));
            }
        }
    } else if claims.sub.starts_with("client:") {
        // 如果是client格式，从数据库中通过用户名查找用户ID
        let username = &claims.sub[7..]; // 移除"client:"前缀
        tracing::debug!("Looking up user by username: {}", username);
        match crate::db::user::get_user_by_username(db, username).await {
            Ok(Some(user)) => {
                tracing::debug!("Found user: {}", user.id);
                user.id
            }
            Ok(None) => {
                tracing::warn!("User not found for username: {}", username);
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "success": false,
                        "error": "User not found",
                    })),
                ));
            }
            Err(e) => {
                tracing::warn!("Database error: {}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "success": false,
                        "error": format!("Failed to find user: {}", e),
                    })),
                ));
            }
        }
    } else {
        // 直接使用sub作为用户ID（OAuth情况）
        tracing::debug!("Using sub directly as user_id: {}", claims.sub);
        claims.sub.clone()
    };

    // 验证新密码长度
    if req.new_password.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "New password must be at least 8 characters long",
            })),
        ));
    }

    match crate::db::user::change_user_password(
        db,
        &user_id,
        &req.current_password,
        &req.new_password,
    )
    .await
    {
        Ok(true) => Ok(Json(json!({
            "success": true,
            "message": "Password changed successfully",
        }))),
        Ok(false) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "Current password is incorrect or user not found",
            })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to change password: {}", e),
            })),
        )),
    }
}

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
    models::{*, Claims},
    state::AppState,
    utils::{require_db, ApiResponse},
};

pub fn user_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/admin/users", get(list_users_handler))
        .route("/v1/admin/users", post(create_user_handler))
        .route("/v1/admin/users/:user_id", get(get_user_handler))
        .route("/v1/admin/users/:user_id", put(update_user_handler))
        .route("/v1/admin/users/:user_id", delete(delete_user_handler))
        .route(
            "/v1/admin/users/:user_id/reset-password",
            post(reset_user_password_handler),
        )
        .route("/v1/user/change-password", post(change_password_handler))
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

async fn get_user_handler(State(state): State<AppState>, Path(user_id): Path<String>) -> ApiResponse {
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
    let user_id = &claims.sub;

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
        user_id,
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

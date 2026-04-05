use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::json;

use crate::db::user::create_user;
use crate::models::CreateUserRequest;
use crate::state::AppState;
use crate::utils::ApiResponse;

/// 用户注册处理器
pub async fn register_user(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> ApiResponse {
    let db = match &state.db {
        Some(db) => db,
        None => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": "Database not available",
                })),
            ));
        }
    };

    // 验证密码长度
    if let Some(ref password) = req.password {
        if password.len() < 8 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "error": "Password must be at least 8 characters long",
                })),
            ));
        }
    }

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
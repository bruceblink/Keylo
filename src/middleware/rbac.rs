use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{Json, Response},
};
use serde_json::json;

use crate::{db::user_has_permission, utils::AppState};

/// 权限检查中间件
pub async fn require_permission<B>(
    State(state): State<AppState>,
    required_permission: String,
    mut request: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    // 从请求扩展中获取用户信息
    let user_id = request
        .extensions()
        .get::<String>()
        .ok_or(StatusCode::UNAUTHORIZED)?
        .clone();

    // 检查用户是否有所需权限
    match user_has_permission(&state.db, &user_id, &required_permission).await {
        Ok(true) => {
            // 用户有权限，继续处理请求
            Ok(next.run(request).await)
        }
        Ok(false) => {
            // 用户没有权限，返回403 Forbidden
            let body = Json(json!({
                "success": false,
                "error": format!("Insufficient permissions. Required: {}", required_permission)
            }));
            let response = (StatusCode::FORBIDDEN, body).into_response();
            Ok(response)
        }
        Err(_) => {
            // 数据库错误，返回500
            let body = Json(json!({
                "success": false,
                "error": "Internal server error"
            }));
            let response = (StatusCode::INTERNAL_SERVER_ERROR, body).into_response();
            Ok(response)
        }
    }
}

/// 创建需要特定权限的中间件
pub fn permission_middleware(permission: &str) -> impl Fn(State<AppState>, Request<axum::body::Body>, Next<axum::body::Body>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>> + Clone {
    let permission = permission.to_string();
    move |state, request, next| {
        let permission = permission.clone();
        Box::pin(require_permission(state, permission, request, next))
    }
}
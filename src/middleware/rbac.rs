use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;

use crate::{db::user_has_permission, models::Claims, state::AppState};

/// 权限检查中间件
pub async fn require_permission(
    State(state): State<AppState>,
    required_permission: String,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let claims = request
        .extensions()
        .get::<Claims>()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let user_id = claims.uid.as_deref().unwrap_or(&claims.sub);

    let db = match state.db.as_deref() {
        Some(db) => db,
        None => {
            let body = Json(json!({
                "success": false,
                "error": "Database not initialized",
            }));
            let response = (StatusCode::INTERNAL_SERVER_ERROR, body).into_response();
            return Ok(response);
        }
    };

    // 检查用户是否有所需权限
    match user_has_permission(db, &user_id, &required_permission).await {
        Ok(true) => Ok(next.run(request).await),
        Ok(false) => {
            let body = Json(json!({
                "success": false,
                "error": format!("Insufficient permissions. Required: {}", required_permission)
            }));
            let response = (StatusCode::FORBIDDEN, body).into_response();
            Ok(response)
        }
        Err(_) => {
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
#[allow(clippy::type_complexity)]
pub fn permission_middleware(
    permission: &str,
) -> impl Fn(
    State<AppState>,
    Request<Body>,
    Next,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>,
> + Clone {
    let permission = permission.to_string();
    move |state, request, next| {
        let permission = permission.clone();
        Box::pin(require_permission(state, permission, request, next))
    }
}

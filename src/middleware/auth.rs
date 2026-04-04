use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::body::Body;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use axum_extra::TypedHeader;
use crate::state::AppState;
use crate::errors::AuthError;

/// 认证中间件 - 检查token是否在黑名单中
pub async fn auth_middleware(
    State(state): State<AppState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = auth.token();

    // 检查token是否在黑名单中
    if let Some(db) = &state.db {
        match crate::db::is_token_blacklisted(db, token).await {
            Ok(true) => {
                // Token在黑名单中，返回401
                let error_response = AuthError::InvalidToken;
                return Ok(error_response.into_response());
            }
            Ok(false) => {
                // Token不在黑名单中，继续处理
            }
            Err(_) => {
                // 数据库错误，返回500
                let error_response = AuthError::DatabaseError("Database error during token validation".to_string());
                return Ok(error_response.into_response());
            }
        }
    }

    // 继续处理请求
    Ok(next.run(request).await)
}
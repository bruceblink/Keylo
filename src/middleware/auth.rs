use crate::errors::AuthError;
use crate::models::Claims;
use crate::state::AppState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;

/// 认证中间件 - 检查token是否在黑名单中
pub async fn auth_middleware(
    State(state): State<AppState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = auth.token();

    // 先验证 JWT 是否有效（签名、过期、aud 等）
    let claims = match state.jwt_keys.decode_token(token) {
        Ok(claims) => claims,
        Err(err) => return Ok(err.into_response()),
    };

    // 仅允许 access token 访问受保护接口
    if claims.token_type != "access" {
        return Ok(AuthError::InvalidToken.into_response());
    }

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
                let error_response =
                    AuthError::DatabaseError("Database error during token validation".to_string());
                return Ok(error_response.into_response());
            }
        }
    }

    // 将 claims 放入扩展，后续中间件或处理器可复用
    request.extensions_mut().insert(claims);

    // 继续处理请求
    Ok(next.run(request).await)
}

/// 管理员权限中间件
pub async fn admin_scope_middleware(
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let claims = match request.extensions().get::<Claims>() {
        Some(claims) => claims,
        None => return Ok(AuthError::Unauthorized.into_response()),
    };

    if !claims.scope.iter().any(|s| s == "admin") {
        return Ok(AuthError::Forbidden.into_response());
    }

    Ok(next.run(request).await)
}

/// 服务间鉴权中间件
/// 验证 Bearer Token 为有效的 service_access JWT，并将 ServiceClaims 注入请求扩展
pub async fn service_auth_middleware(
    State(state): State<AppState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = auth.token();

    let claims = match crate::handlers::service::decode_service_token(&state, token) {
        Ok(c) => c,
        Err(err) => return Ok(err.into_response()),
    };

    if claims.token_type != "service_access" {
        return Ok(AuthError::InvalidToken.into_response());
    }

    // 检查 Token 黑名单
    if let Some(db) = &state.db {
        match crate::db::is_token_blacklisted(db, token).await {
            Ok(true) => return Ok(AuthError::InvalidToken.into_response()),
            Err(_) => {
                return Ok(
                    AuthError::DatabaseError("Token validation failed".to_string()).into_response(),
                )
            }
            Ok(false) => {}
        }
    }

    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}

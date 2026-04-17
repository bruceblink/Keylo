use crate::errors::AuthError;
use crate::models::service::ServiceClaims;
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

fn ensure_access_claims(
    claims: &Claims,
    required_role: Option<&str>,
    required_scope: Option<&str>,
    required_audience: Option<&str>,
) -> Result<(), AuthError> {
    if claims.token_type != "access" {
        return Err(AuthError::TokenTypeInvalid);
    }

    if let Some(role) = required_role {
        if !claims.has_role(role) {
            return Err(AuthError::InsufficientRole);
        }
    }

    if let Some(scope) = required_scope {
        if !claims.has_scope(scope) {
            return Err(AuthError::InsufficientScope);
        }
    }

    if let Some(audience) = required_audience {
        if !claims.has_audience(audience) {
            return Err(AuthError::InvalidAudience);
        }
    }

    Ok(())
}

fn ensure_service_claims(
    claims: &ServiceClaims,
    required_scope: Option<&str>,
    required_audience: Option<&str>,
) -> Result<(), AuthError> {
    if claims.token_type != "service_access" {
        return Err(AuthError::TokenTypeInvalid);
    }

    if claims.role.as_deref() != Some("service") {
        return Err(AuthError::InsufficientRole);
    }

    if let Some(scope) = required_scope {
        if !claims.scope.iter().any(|value| value == scope) {
            return Err(AuthError::InsufficientScope);
        }
    }

    if let Some(audience) = required_audience {
        if claims.aud != audience && claims.aud != "*" {
            return Err(AuthError::InvalidAudience);
        }
    }

    Ok(())
}

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
        return Ok(AuthError::TokenTypeInvalid.into_response());
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

/// 管理端鉴权：仅允许 admin 角色访问管理接口
pub async fn admin_authorization_middleware(
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let claims = match request.extensions().get::<Claims>() {
        Some(claims) => claims,
        None => return Ok(AuthError::Unauthorized.into_response()),
    };

    if let Err(err) =
        ensure_access_claims(claims, Some("admin"), Some("admin"), Some("admin-backend"))
    {
        return Ok(err.into_response());
    }

    Ok(next.run(request).await)
}

/// 用户自助接口鉴权：仅允许 user 角色访问
pub async fn user_authorization_middleware(
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let claims = match request.extensions().get::<Claims>() {
        Some(claims) => claims,
        None => return Ok(AuthError::Unauthorized.into_response()),
    };

    if let Err(err) =
        ensure_access_claims(claims, Some("user"), Some("write"), Some("admin-backend"))
    {
        return Ok(err.into_response());
    }

    Ok(next.run(request).await)
}

/// 服务间鉴权中间件
/// 验证 Bearer Token 为有效的 service_access JWT，并将 ServiceClaims 注入请求扩展
/// aud 字段的精确校验由后续授权中间件（ensure_service_claims）负责
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

/// 面向授权中心集成的服务鉴权：
/// 在 JWT 层严格校验 audience = "admin-backend"（防御纵深），
/// 同时注入 ServiceClaims 供后续 service_integration_authorization_middleware 使用
pub async fn service_integration_auth_middleware(
    State(state): State<AppState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = auth.token();

    let claims = match crate::handlers::service::decode_service_token_for_audience(
        &state,
        token,
        "admin-backend",
    ) {
        Ok(c) => c,
        Err(err) => return Ok(err.into_response()),
    };

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

/// 面向授权中心集成的服务鉴权：需要 service 角色、read scope、admin-backend audience
pub async fn service_integration_authorization_middleware(
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let claims = match request.extensions().get::<ServiceClaims>() {
        Some(claims) => claims,
        None => return Ok(AuthError::Unauthorized.into_response()),
    };

    if let Err(err) = ensure_service_claims(claims, Some("read"), Some("admin-backend")) {
        return Ok(err.into_response());
    }

    Ok(next.run(request).await)
}

/// 服务 token introspect：需要 service 角色和 read scope
pub async fn service_read_authorization_middleware(
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let claims = match request.extensions().get::<ServiceClaims>() {
        Some(claims) => claims,
        None => return Ok(AuthError::Unauthorized.into_response()),
    };

    if let Err(err) = ensure_service_claims(claims, Some("read"), None) {
        return Ok(err.into_response());
    }

    Ok(next.run(request).await)
}

use crate::errors::AuthError;
use crate::models::service::ServiceClaims;
use crate::models::{Claims, USER_CLASS_INTERNAL_EMPLOYEE};
use crate::state::AppState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use serde_json::json;

fn bearer_token(auth: Option<TypedHeader<Authorization<Bearer>>>) -> Result<String, AuthError> {
    auth.map(|TypedHeader(Authorization(bearer))| bearer.token().to_string())
        .ok_or(AuthError::Unauthorized)
}

fn service_id_from_subject(subject: &str) -> Option<&str> {
    subject.strip_prefix("service:")
}

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

/// Revalidates a service JWT against the stored client and tenant boundary.
///
/// Service tokens carry a signed organization id, but organization status and
/// machine membership can change after issuance. Every protected service route
/// therefore checks the immutable client scope and current lifecycle state.
async fn ensure_service_claims_live(
    state: &AppState,
    claims: &ServiceClaims,
) -> Result<(), AuthError> {
    let service_id = service_id_from_subject(&claims.sub).ok_or(AuthError::InvalidToken)?;
    if claims.principal_id.is_none() || claims.principal_type.as_deref() != Some("service") {
        return Err(AuthError::InvalidToken);
    }

    let db = state.db.as_deref().ok_or_else(|| {
        AuthError::DatabaseError("Database required for service authentication".to_string())
    })?;
    let active = crate::db::service::service_token_context_is_active(
        db,
        service_id,
        claims.principal_id.as_deref(),
        claims.organization_id.as_deref(),
    )
    .await
    .map_err(|_| AuthError::DatabaseError("Service authorization failed".to_string()))?;

    active.then_some(()).ok_or(AuthError::Forbidden)
}

/// Reject disabled Principals on every protected request so user disable takes effect immediately.
async fn ensure_claim_principal_active(
    db: &sqlx::PgPool,
    claims: &Claims,
) -> Result<(), AuthError> {
    if let Some(principal_id) = claims.principal_id.as_deref() {
        return crate::db::get_principal_by_id(db, principal_id)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to resolve token principal".to_string()))?
            .filter(|principal| principal.active)
            .map(|_| ())
            .ok_or(AuthError::InvalidToken);
    }
    if claims.principal_type.as_deref() == Some("user") {
        if let Some(user_id) = claims.uid.as_deref() {
            return crate::db::get_user_by_id(db, user_id)
                .await
                .map_err(|_| AuthError::DatabaseError("Failed to resolve token user".to_string()))?
                .filter(|user| user.active)
                .map(|_| ())
                .ok_or(AuthError::InvalidToken);
        }
    }
    Ok(())
}

/// 认证中间件 - 检查token是否在黑名单中
pub async fn auth_middleware(
    State(state): State<AppState>,
    auth: Option<TypedHeader<Authorization<Bearer>>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = match bearer_token(auth) {
        Ok(token) => token,
        Err(err) => return Ok(err.into_response()),
    };

    // 先验证 JWT 是否有效（签名、过期、aud 等）
    let claims = match state.jwt_keys.decode_token(&token) {
        Ok(claims) => claims,
        Err(err) => return Ok(err.into_response()),
    };

    // 仅允许 access token 访问受保护接口
    if claims.token_type != "access" {
        return Ok(AuthError::TokenTypeInvalid.into_response());
    }

    // 检查token是否在黑名单中
    if let Some(db) = &state.db {
        match crate::db::is_token_blacklisted(db, &token).await {
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
        if let Err(error) = ensure_claim_principal_active(db, &claims).await {
            return Ok(error.into_response());
        }
    }

    // 将 claims 放入扩展，后续中间件或处理器可复用
    request.extensions_mut().insert(claims);

    // 继续处理请求
    Ok(next.run(request).await)
}

/// 管理端鉴权：仅允许 admin 角色访问管理接口
pub async fn admin_authorization_middleware(
    State(state): State<AppState>,
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

    // Recheck live authority rather than trusting a still-signed admin claim.
    // This closes access immediately when a human is reclassified or a client
    // loses its admin flag.
    let db = match state.db.as_deref() {
        Some(db) => db,
        None => {
            return Ok(AuthError::DatabaseError(
                "Database unavailable for platform access check".to_string(),
            )
            .into_response())
        }
    };
    let live_admin = match claims.principal_type.as_deref() {
        Some("user") => {
            let Some(user_id) = claims.uid.as_deref() else {
                return Ok(AuthError::InvalidToken.into_response());
            };
            match crate::db::user_is_platform_admin(db, user_id).await {
                Ok(allowed) => allowed,
                Err(_) => {
                    return Ok(AuthError::DatabaseError(
                        "Database error during platform access check".to_string(),
                    )
                    .into_response())
                }
            }
        }
        Some("client") => {
            let Some(client_id) = claims.sub.strip_prefix("client:") else {
                return Ok(AuthError::InvalidToken.into_response());
            };
            match crate::db::get_client_auth_info(db, client_id).await {
                Ok(Some((_, is_admin))) => is_admin,
                Ok(None) => false,
                Err(_) => {
                    return Ok(AuthError::DatabaseError(
                        "Database error during platform access check".to_string(),
                    )
                    .into_response())
                }
            }
        }
        _ => return Ok(AuthError::InsufficientRole.into_response()),
    };
    if !live_admin {
        return Ok(AuthError::InsufficientRole.into_response());
    }

    if request.method() != Method::GET && claims.principal_type.as_deref() == Some("user") {
        if let Some(user_id) = claims.uid.as_deref() {
            let mfa_enabled = match crate::db::get_totp_credential(db, user_id).await {
                Ok(credential) => {
                    credential.is_some_and(|credential| credential.enabled_at.is_some())
                }
                Err(_) => {
                    return Ok(AuthError::DatabaseError(
                        "Database error during MFA check".to_string(),
                    )
                    .into_response())
                }
            };
            if state.config.mfa_require_for_admins && !mfa_enabled {
                return Ok((
                    StatusCode::FORBIDDEN,
                    axum::Json(json!({
                        "success": false,
                        "error": "MFA enrollment is required for administrators",
                        "mfa_enrollment_required": true,
                    })),
                )
                    .into_response());
            }
            if mfa_enabled {
                match crate::db::has_recent_mfa_verification(db, user_id, &claims.jti).await {
                    Ok(true) => {}
                    Ok(false) => {
                        return Ok((
                            StatusCode::FORBIDDEN,
                            axum::Json(json!({
                                "success": false,
                                "error": "Recent MFA verification is required",
                                "mfa_required": true,
                            })),
                        )
                            .into_response())
                    }
                    Err(_) => {
                        return Ok(AuthError::DatabaseError(
                            "Database error during MFA verification check".to_string(),
                        )
                        .into_response())
                    }
                }
            }
        }
    }

    Ok(next.run(request).await)
}

/// Restricts platform-wide organization management to platform operators.
///
/// Human account class is loaded from the database on every request so moving
/// an account out of the internal workforce takes effect before its JWT expires.
pub async fn platform_admin_authorization_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let claims = match request.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return Ok(AuthError::Unauthorized.into_response()),
    };
    let db = match state.db.as_deref() {
        Some(db) => db,
        None => {
            return Ok(AuthError::DatabaseError(
                "Database unavailable for platform access check".to_string(),
            )
            .into_response())
        }
    };

    let access_allowed = match claims.principal_type.as_deref() {
        Some("user") => {
            let Some(user_id) = claims.uid.as_deref() else {
                return Ok(AuthError::InvalidToken.into_response());
            };
            match crate::db::get_user_by_id(db, user_id).await {
                Ok(Some(user)) if user.active => user.user_class == USER_CLASS_INTERNAL_EMPLOYEE,
                Ok(Some(_)) => return Ok(AuthError::InvalidToken.into_response()),
                Ok(None) => return Ok(AuthError::InvalidToken.into_response()),
                Err(_) => {
                    return Ok(AuthError::DatabaseError(
                        "Database error during platform access check".to_string(),
                    )
                    .into_response())
                }
            }
        }
        Some("client") => {
            let Some(client_id) = claims.sub.strip_prefix("client:") else {
                return Ok(AuthError::InvalidToken.into_response());
            };
            match crate::db::get_client_auth_info(db, client_id).await {
                Ok(Some((_, is_admin_client))) => is_admin_client,
                Ok(None) => return Ok(AuthError::InvalidToken.into_response()),
                Err(_) => {
                    return Ok(AuthError::DatabaseError(
                        "Database error during platform access check".to_string(),
                    )
                    .into_response())
                }
            }
        }
        _ => return Ok(AuthError::InsufficientRole.into_response()),
    };

    if !access_allowed {
        return Ok(AuthError::Forbidden.into_response());
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
    auth: Option<TypedHeader<Authorization<Bearer>>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = match bearer_token(auth) {
        Ok(token) => token,
        Err(err) => return Ok(err.into_response()),
    };

    let claims = match crate::handlers::service::decode_service_token(&state, &token) {
        Ok(c) => c,
        Err(err) => return Ok(err.into_response()),
    };

    // 检查 Token 黑名单
    if let Some(db) = &state.db {
        match crate::db::is_token_blacklisted(db, &token).await {
            Ok(true) => return Ok(AuthError::InvalidToken.into_response()),
            Err(_) => {
                return Ok(
                    AuthError::DatabaseError("Token validation failed".to_string()).into_response(),
                )
            }
            Ok(false) => {}
        }
    }

    if let Err(err) = ensure_service_claims_live(&state, &claims).await {
        return Ok(err.into_response());
    }

    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}

/// 面向授权中心集成的服务鉴权：
/// 在 JWT 层严格校验 audience = "admin-backend"（防御纵深），
/// 同时注入 ServiceClaims 供后续 service_integration_authorization_middleware 使用
pub async fn service_integration_auth_middleware(
    State(state): State<AppState>,
    auth: Option<TypedHeader<Authorization<Bearer>>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = match bearer_token(auth) {
        Ok(token) => token,
        Err(err) => return Ok(err.into_response()),
    };

    let claims = match crate::handlers::service::decode_service_token_for_audience(
        &state,
        &token,
        "admin-backend",
    ) {
        Ok(c) => c,
        Err(err) => return Ok(err.into_response()),
    };

    // 检查 Token 黑名单
    if let Some(db) = &state.db {
        match crate::db::is_token_blacklisted(db, &token).await {
            Ok(true) => return Ok(AuthError::InvalidToken.into_response()),
            Err(_) => {
                return Ok(
                    AuthError::DatabaseError("Token validation failed".to_string()).into_response(),
                )
            }
            Ok(false) => {}
        }
    }

    if let Err(err) = ensure_service_claims_live(&state, &claims).await {
        return Ok(err.into_response());
    }

    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}

/// 面向授权中心集成的服务鉴权：需要 service 角色、read scope、admin-backend audience
pub async fn service_integration_authorization_middleware(
    State(state): State<AppState>,
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

    let Some(service_id) = service_id_from_subject(&claims.sub) else {
        return Ok(AuthError::InvalidToken.into_response());
    };

    let allowed = if let Some(db) = &state.db {
        match crate::db::service::service_introspection_allowed(db, service_id).await {
            Ok(allowed) => allowed,
            Err(_) => {
                return Ok(
                    AuthError::DatabaseError("Service authorization failed".to_string())
                        .into_response(),
                )
            }
        }
    } else {
        false
    };

    if !allowed {
        return Ok(AuthError::Forbidden.into_response());
    }

    Ok(next.run(request).await)
}

/// 服务 token introspect：需要 service 角色和 read scope
pub async fn service_read_authorization_middleware(
    State(state): State<AppState>,
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

    let Some(service_id) = service_id_from_subject(&claims.sub) else {
        return Ok(AuthError::InvalidToken.into_response());
    };

    let allowed = if let Some(db) = &state.db {
        match crate::db::service::service_introspection_allowed(db, service_id).await {
            Ok(allowed) => allowed,
            Err(_) => {
                return Ok(
                    AuthError::DatabaseError("Service authorization failed".to_string())
                        .into_response(),
                )
            }
        }
    } else {
        false
    };

    if !allowed {
        return Ok(AuthError::Forbidden.into_response());
    }

    Ok(next.run(request).await)
}

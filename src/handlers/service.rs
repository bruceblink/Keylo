use crate::db::service as svc_db;
use crate::errors::AuthError;
use crate::models::service::{
    IntrospectRequest, IntrospectResponse, RegisterServiceRequest, RotateServiceSecretRequest,
    ServiceClaims, ServiceInfo, ServiceTokenRequest, ServiceTokenResponse, UpdateServiceRequest,
};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use jsonwebtoken::{encode, Header};
use serde_json::{json, Value};
use uuid::Uuid;

/// POST /v1/service/token
/// 服务间认证：使用 service_id + service_secret 换取短期 JWT
pub async fn service_token(
    State(state): State<AppState>,
    Json(payload): Json<ServiceTokenRequest>,
) -> Result<Json<ServiceTokenResponse>, AuthError> {
    if payload.service_id.is_empty() || payload.service_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    // 优先从数据库验证凭证
    if let Some(db) = &state.db {
        let result =
            svc_db::verify_service_credentials(db, &payload.service_id, &payload.service_secret)
                .await
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        match result {
            None => {
                audit_service_event(
                    &state,
                    "service.token.failed",
                    Some(&payload.service_id),
                    Some("Invalid service credentials"),
                )
                .await;
                return Err(AuthError::WrongCredentials);
            }
            Some((allowed_scopes, allowed_audiences)) => {
                let granted_scopes = resolve_scopes(&payload.scope, &allowed_scopes)?;
                let audience = resolve_audience(&payload.audience, &allowed_audiences)?;

                let token = mint_service_token(
                    &state,
                    &payload.service_id,
                    &granted_scopes,
                    &audience,
                )?;

                audit_service_event(
                    &state,
                    "service.token.issued",
                    Some(&payload.service_id),
                    Some(&format!("scope={}, aud={}", granted_scopes.join(" "), audience)),
                )
                .await;

                let expires_in = state.config.service_token_expiry_seconds;
                return Ok(Json(ServiceTokenResponse::new(
                    token,
                    expires_in,
                    &granted_scopes,
                )));
            }
        }
    }

    // 无数据库时不支持服务间认证
    Err(AuthError::DatabaseError(
        "Database required for service authentication".to_string(),
    ))
}

/// POST /v1/service/introspect
/// Token 内省：验证服务 Token 并返回其 Claims（遵循 RFC 7662）
/// 此端点本身也需要合法的服务 Token 才能访问（由 service_auth_middleware 保护）
pub async fn service_introspect(
    State(state): State<AppState>,
    Json(payload): Json<IntrospectRequest>,
) -> Json<IntrospectResponse> {
    if payload.token.is_empty() {
        return Json(IntrospectResponse::inactive());
    }

    match decode_service_token(&state, &payload.token) {
        Ok(claims) => {
            // 检查 Token 是否在黑名单
            if let Some(db) = &state.db {
                if crate::db::is_token_blacklisted(db, &payload.token)
                    .await
                    .unwrap_or(false)
                {
                    return Json(IntrospectResponse::inactive());
                }
            }
            Json(IntrospectResponse::from_claims(&claims))
        }
        Err(_) => Json(IntrospectResponse::inactive()),
    }
}

// ─── 管理接口 ────────────────────────────────────────────────────────────────

/// GET /v1/admin/services
pub async fn list_services(
    State(state): State<AppState>,
) -> Result<Json<Value>, AuthError> {
    let db = state
        .db
        .as_ref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;

    let services = svc_db::list_service_clients(db)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({ "services": services })))
}

/// POST /v1/admin/services
pub async fn register_service(
    State(state): State<AppState>,
    Json(payload): Json<RegisterServiceRequest>,
) -> Result<Json<Value>, AuthError> {
    if payload.service_id.is_empty() || payload.service_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    let db = state
        .db
        .as_ref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;

    svc_db::create_service_client(
        db,
        &payload.service_id,
        &payload.service_secret,
        &payload.name,
        payload.description.as_deref(),
        &payload.allowed_scopes,
        &payload.allowed_audiences,
    )
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate key") {
            AuthError::InternalServerError(format!(
                "Service '{}' already exists",
                payload.service_id
            ))
        } else {
            AuthError::DatabaseError(e.to_string())
        }
    })?;

    audit_service_event(
        &state,
        "service.registered",
        Some(&payload.service_id),
        Some(&payload.name),
    )
    .await;

    Ok(Json(json!({
        "service_id": payload.service_id,
        "message": "Service registered successfully"
    })))
}

/// PUT /v1/admin/services/{service_id}
pub async fn update_service(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Json(payload): Json<UpdateServiceRequest>,
) -> Result<Json<Value>, AuthError> {
    let db = state
        .db
        .as_ref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;

    let updated = svc_db::update_service_client(
        db,
        &service_id,
        payload.name.as_deref(),
        payload.description.as_deref(),
        payload.allowed_scopes.as_deref(),
        payload.allowed_audiences.as_deref(),
        payload.active,
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    if !updated {
        return Err(AuthError::NotFound);
    }

    audit_service_event(
        &state,
        "service.updated",
        Some(&service_id),
        None,
    )
    .await;

    Ok(Json(json!({ "message": "Service updated successfully" })))
}

/// POST /v1/admin/services/{service_id}/rotate-secret
pub async fn rotate_service_secret(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Json(payload): Json<RotateServiceSecretRequest>,
) -> Result<Json<Value>, AuthError> {
    let db = state
        .db
        .as_ref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;

    let new_secret = payload
        .new_secret
        .unwrap_or_else(svc_db::generate_service_secret);

    let rotated = svc_db::rotate_service_secret(db, &service_id, &new_secret)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    if !rotated {
        return Err(AuthError::NotFound);
    }

    audit_service_event(
        &state,
        "service.secret.rotated",
        Some(&service_id),
        None,
    )
    .await;

    Ok(Json(json!({
        "service_id": service_id,
        "new_secret": new_secret,
        "message": "Service secret rotated successfully. Store the new secret securely."
    })))
}

/// GET /v1/admin/services/{service_id}
pub async fn get_service(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
) -> Result<Json<ServiceInfo>, AuthError> {
    let db = state
        .db
        .as_ref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;

    let service = svc_db::get_service_client(db, &service_id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        .ok_or(AuthError::NotFound)?;

    Ok(Json(service))
}

// ─── 内部工具函数 ─────────────────────────────────────────────────────────────

/// 签发服务 JWT
pub fn mint_service_token(
    state: &AppState,
    service_id: &str,
    scopes: &[String],
    audience: &str,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let exp = now + state.config.service_token_expiry_seconds;

    let claims = ServiceClaims {
        sub: format!("service:{}", service_id),
        iss: "keylo".to_string(),
        aud: audience.to_string(),
        scope: scopes.to_vec(),
        token_type: "service_access".to_string(),
        exp,
        iat: now,
        jti: Uuid::new_v4().to_string(),
    };

    encode(&Header::default(), &claims, &state.jwt_keys.encoding)
        .map_err(|_| AuthError::TokenCreation)
}

/// 解码并验证服务 Token（不检查 aud，允许任意 audience）
pub fn decode_service_token(
    state: &AppState,
    token: &str,
) -> Result<ServiceClaims, AuthError> {
    state.jwt_keys.decode_service_token(token)
}

/// 解析请求的 scope：必须是 allowed_scopes 的子集
fn resolve_scopes(
    requested: &Option<String>,
    allowed: &[String],
) -> Result<Vec<String>, AuthError> {
    match requested {
        None => Ok(allowed.to_vec()),
        Some(req) => {
            let requested_scopes: Vec<String> =
                req.split_whitespace().map(|s| s.to_string()).collect();
            for scope in &requested_scopes {
                if !allowed.contains(scope) {
                    return Err(AuthError::Forbidden);
                }
            }
            Ok(requested_scopes)
        }
    }
}

/// 解析请求的 audience：必须在 allowed_audiences 范围内（或为通配 "*"）
fn resolve_audience(
    requested: &Option<String>,
    allowed: &[String],
) -> Result<String, AuthError> {
    let wildcard = "*".to_string();

    match requested {
        None => {
            // 未指定：若只有一个 audience 则使用它，否则用通配
            if allowed.len() == 1 {
                Ok(allowed[0].clone())
            } else if allowed.contains(&wildcard) {
                Ok(wildcard)
            } else {
                Err(AuthError::MissingCredentials)
            }
        }
        Some(aud) => {
            if allowed.contains(aud) || allowed.contains(&wildcard) {
                Ok(aud.clone())
            } else {
                Err(AuthError::Forbidden)
            }
        }
    }
}

async fn audit_service_event(
    state: &AppState,
    event_type: &str,
    actor: Option<&str>,
    detail: Option<&str>,
) {
    if let Some(db) = &state.db {
        if let Err(err) = crate::db::create_audit_log(db, event_type, actor, detail).await {
            tracing::warn!("Failed to write service audit log: {}", err);
        }
    }
}

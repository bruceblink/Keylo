use crate::db::service as svc_db;
use crate::errors::{is_unique_violation, AuthError};
use crate::models::service::{
    IntrospectRequest, IntrospectResponse, RegisterServiceRequest, RotateServiceSecretRequest,
    ServiceClaims, ServiceInfo, ServiceTokenRequest, ServiceTokenResponse, UpdateServiceRequest,
};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use uuid::Uuid;

/// POST /v1/service/token
/// 服务间认证：使用 service_id + service_secret 换取短期 JWT
pub async fn service_token(
    State(state): State<AppState>,
    Json(payload): Json<ServiceTokenRequest>,
) -> Result<Json<ServiceTokenResponse>, AuthError> {
    if payload.service_id.trim().is_empty() || payload.service_secret.trim().is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    // 优先从数据库验证凭证
    if let Some(db) = &state.db {
        let result =
            svc_db::verify_service_credentials(db, &payload.service_id, &payload.service_secret)
                .await
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        match result {
            svc_db::ServiceCredentialVerification::NotAuthorized => {
                audit_service_event(
                    &state,
                    "service.token.forbidden",
                    Some(&payload.service_id),
                    Some("Service client is not registered or active"),
                )
                .await;
                return Err(AuthError::ServiceClientNotAuthorized);
            }
            svc_db::ServiceCredentialVerification::WrongSecret => {
                audit_service_event(
                    &state,
                    "service.token.failed",
                    Some(&payload.service_id),
                    Some("Invalid service credentials"),
                )
                .await;
                return Err(AuthError::WrongCredentials);
            }
            svc_db::ServiceCredentialVerification::Authorized(policy) => {
                let granted_scopes = resolve_scopes(&payload.scope, &policy.allowed_scopes)?;
                let audience = resolve_audience(&payload.audience, &policy.allowed_audiences)?;
                let expires_in = policy
                    .token_ttl_seconds
                    .unwrap_or(state.config.service_token_expiry_seconds);

                let token = mint_service_token(
                    &state,
                    &payload.service_id,
                    &granted_scopes,
                    &audience,
                    expires_in,
                )?;

                audit_service_event(
                    &state,
                    "service.token.issued",
                    Some(&payload.service_id),
                    Some(&format!(
                        "scope={}, aud={}",
                        granted_scopes.join(" "),
                        audience
                    )),
                )
                .await;

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

fn require_db(state: &AppState) -> Result<&sqlx::PgPool, AuthError> {
    state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))
}

/// GET /v1/admin/services
pub async fn list_services(State(state): State<AppState>) -> Result<Json<Value>, AuthError> {
    let db = require_db(&state)?;

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
    if payload.service_id.trim().is_empty()
        || payload.service_secret.trim().is_empty()
        || payload.name.trim().is_empty()
    {
        return Err(AuthError::MissingCredentials);
    }
    if payload
        .token_ttl_seconds
        .is_some_and(|ttl| ttl <= 0 || ttl > state.config.refresh_token_expiry_seconds)
    {
        return Err(AuthError::InvalidRequest(format!(
            "token_ttl_seconds must be between 1 and {}",
            state.config.refresh_token_expiry_seconds
        )));
    }
    let allowed_scopes = normalize_list("allowed_scopes", payload.allowed_scopes, false)?;
    let allowed_audiences = normalize_list("allowed_audiences", payload.allowed_audiences, true)?;

    let db = require_db(&state)?;
    let integration_type = normalized_or_default(payload.integration_type.as_deref(), "internal");
    let owner = payload.owner.as_deref().and_then(non_empty_trimmed);
    let contact = payload.contact.as_deref().and_then(non_empty_trimmed);

    svc_db::create_service_client(
        db,
        &payload.service_id,
        &payload.service_secret,
        &payload.name,
        payload.description.as_deref(),
        &allowed_scopes,
        &allowed_audiences,
        &integration_type,
        payload.introspection_allowed.unwrap_or(true),
        payload.token_ttl_seconds,
        owner.as_deref(),
        contact.as_deref(),
    )
    .await
    .map_err(|e| {
        if is_unique_violation(e.as_ref()) {
            AuthError::Conflict(format!(
                "Service client '{}' already exists; choose a different service_id or update the existing service.",
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
    let db = require_db(&state)?;
    if payload
        .token_ttl_seconds
        .is_some_and(|ttl| ttl <= 0 || ttl > state.config.refresh_token_expiry_seconds)
    {
        return Err(AuthError::InvalidRequest(format!(
            "token_ttl_seconds must be between 1 and {}",
            state.config.refresh_token_expiry_seconds
        )));
    }
    let integration_type = payload
        .integration_type
        .as_deref()
        .and_then(non_empty_trimmed);
    let allowed_scopes = payload
        .allowed_scopes
        .map(|values| normalize_list("allowed_scopes", values, false))
        .transpose()?;
    let allowed_audiences = payload
        .allowed_audiences
        .map(|values| normalize_list("allowed_audiences", values, true))
        .transpose()?;
    let owner = payload.owner.as_deref().and_then(non_empty_trimmed);
    let contact = payload.contact.as_deref().and_then(non_empty_trimmed);

    let updated = svc_db::update_service_client(
        db,
        &service_id,
        payload.name.as_deref(),
        payload.description.as_deref(),
        allowed_scopes.as_deref(),
        allowed_audiences.as_deref(),
        payload.active,
        integration_type.as_deref(),
        payload.introspection_allowed,
        payload.token_ttl_seconds,
        owner.as_deref(),
        contact.as_deref(),
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    if !updated {
        return Err(AuthError::NotFound);
    }

    audit_service_event(&state, "service.updated", Some(&service_id), None).await;

    Ok(Json(json!({ "message": "Service updated successfully" })))
}

/// POST /v1/admin/services/{service_id}/rotate-secret
pub async fn rotate_service_secret(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Json(payload): Json<RotateServiceSecretRequest>,
) -> Result<Json<Value>, AuthError> {
    let db = require_db(&state)?;

    let provided_secret = payload
        .new_secret
        .as_deref()
        .filter(|secret| !secret.trim().is_empty());
    let generated_secret = provided_secret.is_none();
    let new_secret = provided_secret
        .map(str::to_string)
        .unwrap_or_else(svc_db::generate_service_secret);

    let rotated = svc_db::rotate_service_secret(db, &service_id, &new_secret)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    if !rotated {
        return Err(AuthError::NotFound);
    }

    audit_service_event(&state, "service.secret.rotated", Some(&service_id), None).await;

    let mut response = json!({
        "service_id": service_id,
        "message": "Service secret rotated successfully",
        "secret_generated": generated_secret
    });
    if generated_secret {
        response["new_secret"] = json!(new_secret);
    }

    Ok(Json(response))
}

/// GET /v1/admin/services/{service_id}
pub async fn get_service(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
) -> Result<Json<ServiceInfo>, AuthError> {
    let db = require_db(&state)?;

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
    expires_in: i64,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let exp = now + expires_in;

    let claims = ServiceClaims {
        sub: format!("service:{}", service_id),
        iss: state.config.jwt_issuer.clone(),
        aud: audience.to_string(),
        scope: scopes.to_vec(),
        role: Some("service".to_string()),
        token_type: "service_access".to_string(),
        exp,
        iat: now,
        jti: Uuid::new_v4().to_string(),
    };

    state.jwt_keys.sign_token(&claims)
}

/// 解码并验证服务 Token（不检查 aud，允许任意 audience）
pub fn decode_service_token(state: &AppState, token: &str) -> Result<ServiceClaims, AuthError> {
    state.jwt_keys.decode_service_token(token)
}

/// 解码并验证服务 Token，同时在 JWT 层强制校验 audience（防御纵深）
pub fn decode_service_token_for_audience(
    state: &AppState,
    token: &str,
    expected_audience: &str,
) -> Result<ServiceClaims, AuthError> {
    state
        .jwt_keys
        .decode_service_token_for_audience(token, expected_audience)
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
fn resolve_audience(requested: &Option<String>, allowed: &[String]) -> Result<String, AuthError> {
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

fn non_empty_trimmed(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalized_or_default(value: Option<&str>, default: &str) -> String {
    value
        .and_then(non_empty_trimmed)
        .unwrap_or_else(|| default.to_string())
}

fn normalize_list(
    field_name: &str,
    values: Vec<String>,
    allow_wildcard: bool,
) -> Result<Vec<String>, AuthError> {
    let mut normalized = BTreeSet::new();

    for value in values {
        let item = value.trim();
        if item.is_empty() {
            return Err(AuthError::InvalidRequest(format!(
                "{} must not contain empty values",
                field_name
            )));
        }
        if item.split_whitespace().count() != 1 {
            return Err(AuthError::InvalidRequest(format!(
                "{} values must not contain whitespace",
                field_name
            )));
        }
        if item == "*" && !allow_wildcard {
            return Err(AuthError::InvalidRequest(format!(
                "{} does not allow wildcard values",
                field_name
            )));
        }

        normalized.insert(item.to_string());
    }

    if normalized.is_empty() {
        return Err(AuthError::InvalidRequest(format!(
            "{} must contain at least one value",
            field_name
        )));
    }

    Ok(normalized.into_iter().collect())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_list_trims_deduplicates_and_sorts_values() {
        let values = vec![
            " write ".to_string(),
            "read".to_string(),
            "write".to_string(),
        ];

        let normalized = normalize_list("allowed_scopes", values, false).unwrap();

        assert_eq!(normalized, vec!["read".to_string(), "write".to_string()]);
    }

    #[test]
    fn normalize_list_rejects_empty_values() {
        let err =
            normalize_list("allowed_scopes", vec!["read".into(), " ".into()], false).unwrap_err();

        assert!(matches!(err, AuthError::InvalidRequest(_)));
    }

    #[test]
    fn normalize_list_rejects_scope_wildcard() {
        let err = normalize_list("allowed_scopes", vec!["*".into()], false).unwrap_err();

        assert!(matches!(err, AuthError::InvalidRequest(_)));
    }

    #[test]
    fn normalize_list_allows_audience_wildcard() {
        let normalized = normalize_list("allowed_audiences", vec!["*".into()], true).unwrap();

        assert_eq!(normalized, vec!["*".to_string()]);
    }
}

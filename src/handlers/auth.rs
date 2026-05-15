use crate::db::user::get_user_by_username;
use crate::errors::{is_unique_violation, AuthError};
use crate::models::{
    AuthBody, AuthPayload, BlacklistTokenRequest, Claims, CleanupAuditLogsRequest,
    CreateClientRequest, IntrospectTokenRequest, KeyloConfiguration, MeResponse,
    RefreshTokenRequest, RotateClientSecretRequest, TokenIntrospectResponse, UpdateClientRequest,
};
use crate::state::AppState;
use crate::utils;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use bcrypt::verify;
use chrono::Utc;
use http::request::Parts;
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};

fn access_scope(_subject_prefix: &str, is_admin_client: bool) -> Vec<String> {
    if is_admin_client {
        vec!["read".into(), "write".into(), "admin".into()]
    } else {
        vec!["read".into(), "write".into()]
    }
}

pub struct PeerAddr(Option<SocketAddr>);

impl<S> axum::extract::FromRequestParts<S> for PeerAddr
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| *addr),
        ))
    }
}

fn claim_role(subject_prefix: &str, is_admin_client: bool) -> Vec<String> {
    match subject_prefix {
        "user" if is_admin_client => vec!["admin".to_string()],
        "user" => vec!["user".to_string()],
        "client" if is_admin_client => vec!["admin".to_string()],
        _ => Vec::new(),
    }
}

async fn is_user_admin(db: &sqlx::PgPool, user_id: &str) -> bool {
    crate::db::user_has_role(db, user_id, "super_admin")
        .await
        .unwrap_or(false)
        || crate::db::user_has_role(db, user_id, "admin")
            .await
            .unwrap_or(false)
}

fn require_admin_scope(claims: &Claims) -> Result<(), AuthError> {
    if claims.has_scope("admin") {
        Ok(())
    } else {
        Err(AuthError::Forbidden)
    }
}

fn require_db(state: &AppState) -> Result<&sqlx::PgPool, AuthError> {
    state
        .db
        .as_deref()
        .ok_or_else(|| db_error("Database not available"))
}

fn db_error(message: &str) -> AuthError {
    AuthError::DatabaseError(message.to_string())
}

async fn audit_event(
    state: &AppState,
    event_type: &str,
    actor: Option<&str>,
    detail: Option<&str>,
) {
    if let Some(db) = &state.db {
        if let Err(err) = crate::db::create_audit_log(db, event_type, actor, detail).await {
            tracing::warn!("Failed to write audit log: {}", err);
        }
    }
}
fn audit_event_background(
    state: &AppState,
    event_type: &str,
    actor: Option<&str>,
    detail: Option<&str>,
) {
    let Some(db) = state.db.as_ref().cloned() else {
        return;
    };

    let event_type = event_type.to_string();
    let actor = actor.map(|s| s.to_string());
    let detail = detail.map(|s| s.to_string());

    tokio::spawn(async move {
        if let Err(err) =
            crate::db::create_audit_log(&db, &event_type, actor.as_deref(), detail.as_deref()).await
        {
            tracing::warn!("Failed to write audit log: {}", err);
        }
    });
}

fn extract_client_ip(
    headers: &HeaderMap,
    peer_addr: Option<SocketAddr>,
    trust_proxy_headers: bool,
) -> String {
    if trust_proxy_headers {
        if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = value.split(',').next() {
                let ip = first.trim();
                if !ip.is_empty() && ip.parse::<std::net::IpAddr>().is_ok() {
                    return ip.to_string();
                }
            }
        }

        if let Some(value) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            let ip = value.trim();
            if !ip.is_empty() && ip.parse::<std::net::IpAddr>().is_ok() {
                return ip.to_string();
            }
        }
    }

    peer_addr
        .map(|addr| normalize_ip(addr.ip()).to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(value) => value
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(value)),
        IpAddr::V4(value) => IpAddr::V4(value),
    }
}

pub async fn auth_token(
    State(state): State<AppState>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Json(payload): Json<AuthPayload>,
) -> Result<Json<AuthBody>, AuthError> {
    // Check if the user sent the credentials
    if payload.client_id.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    let client_ip = extract_client_ip(&headers, peer_addr, state.config.trust_proxy_headers);
    let scoped_rate_key = format!("{}:{}", client_ip, payload.client_id);
    let global_rate_key = format!("global:{}", client_ip);

    if !state
        .allow_auth_request(
            &global_rate_key,
            state.config.auth_rate_limit_window_seconds,
            state.config.auth_global_rate_limit_max_requests,
        )
        .await
    {
        audit_event(
            &state,
            "auth.token.rate_limited.global",
            Some(&payload.client_id),
            Some("Global auth request rate limit exceeded"),
        )
        .await;
        return Err(AuthError::TooManyRequests);
    }

    if !state
        .allow_auth_request(
            &scoped_rate_key,
            state.config.auth_rate_limit_window_seconds,
            state.config.auth_rate_limit_max_requests,
        )
        .await
    {
        audit_event(
            &state,
            "auth.token.rate_limited",
            Some(&payload.client_id),
            Some("Auth request rate limit exceeded"),
        )
        .await;
        return Err(AuthError::TooManyRequests);
    }

    if state.is_login_locked(&payload.client_id).await.is_some() {
        audit_event(
            &state,
            "auth.token.locked",
            Some(&payload.client_id),
            Some("Login is locked due to repeated failures"),
        )
        .await;
        return Err(AuthError::TooManyRequests);
    }

    let db = require_db(&state)?;

    // First try to authenticate as a user
    let user_result = get_user_by_username(db, &payload.client_id).await;
    let (is_user_valid, user_id) = match user_result {
        Ok(Some(user)) => {
            if !user.active {
                (false, None)
            } else if let Some(ref password_hash) = user.password_hash {
                let result = verify(&payload.client_secret, password_hash)
                    .map_err(|_| AuthError::WrongCredentials)?;
                (result, Some(user.id))
            } else {
                tracing::debug!("User has no password hash: {}", payload.client_id);
                (false, None)
            }
        }
        Ok(None) => {
            tracing::debug!("User not found: {}", payload.client_id);
            (false, None)
        }
        Err(e) => {
            tracing::warn!("Database error getting user: {:?}", e);
            return Err(AuthError::DatabaseError("Failed to get user".to_string()));
        }
    };

    if !is_user_valid {
        state
            .record_login_failure(
                &payload.client_id,
                state.config.max_failed_login_attempts,
                state.config.login_lockout_seconds,
            )
            .await;
        audit_event(
            &state,
            "auth.token.failed",
            Some(&payload.client_id),
            Some("Wrong credentials"),
        )
        .await;
        return Err(AuthError::WrongCredentials);
    }

    state.clear_login_failures(&payload.client_id).await;
    audit_event(
        &state,
        "auth.token.success",
        Some(&payload.client_id),
        Some("Access token issued"),
    )
    .await;

    let now = Utc::now().timestamp();
    let subject_prefix = "user";
    let is_admin_user = if let Some(user_id) = user_id.as_deref() {
        is_user_admin(db, user_id).await
    } else {
        false
    };

    // Create access token claims
    let access_claims = Claims {
        sub: format!("{}:{}", subject_prefix, payload.client_id),
        uid: user_id.clone(),
        iss: state.config.jwt_issuer.clone(),
        aud: "admin-backend".to_string(),
        scope: access_scope(subject_prefix, is_admin_user),
        role: claim_role(subject_prefix, is_admin_user),
        iat: now,
        exp: now + state.config.token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "access".to_string(),
    };

    let access_token = state.jwt_keys.sign_token(&access_claims)?;

    // Send the authorized tokens
    Ok(Json(AuthBody::new(
        access_token,
        None,
        state.config.token_expiry_seconds,
    )))
}

pub async fn admin_token(
    State(state): State<AppState>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Json(payload): Json<AuthPayload>,
) -> Result<Json<AuthBody>, AuthError> {
    if payload.client_id.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    let client_ip = extract_client_ip(&headers, peer_addr, state.config.trust_proxy_headers);
    let scoped_rate_key = format!("{}:{}", client_ip, payload.client_id);
    let global_rate_key = format!("global:{}", client_ip);

    if !state
        .allow_auth_request_pair(
            &global_rate_key,
            state.config.auth_global_rate_limit_max_requests,
            &scoped_rate_key,
            state.config.auth_rate_limit_max_requests,
            state.config.auth_rate_limit_window_seconds,
        )
        .await
    {
        return Err(AuthError::TooManyRequests);
    }

    if state.is_login_locked(&payload.client_id).await.is_some() {
        return Err(AuthError::TooManyRequests);
    }

    let db = state
        .db
        .as_deref()
        .ok_or_else(|| db_error("Database not available"))?;

    let (stored_secret, is_admin_client) =
        match crate::db::get_client_auth_info(db, &payload.client_id).await {
            Ok(Some((secret, is_admin))) => (secret, is_admin),
            Ok(None) => {
                state
                    .record_login_failure(
                        &payload.client_id,
                        state.config.max_failed_login_attempts,
                        state.config.login_lockout_seconds,
                    )
                    .await;
                return Err(AuthError::WrongCredentials);
            }
            Err(_) => return Err(AuthError::DatabaseError("Failed to get client".to_string())),
        };

    if !verify(&payload.client_secret, &stored_secret).unwrap_or(false) {
        state
            .record_login_failure(
                &payload.client_id,
                state.config.max_failed_login_attempts,
                state.config.login_lockout_seconds,
            )
            .await;
        audit_event_background(
            &state,
            "admin.token.failed",
            Some(&payload.client_id),
            Some("Wrong credentials"),
        );
        return Err(AuthError::WrongCredentials);
    }

    if !is_admin_client {
        audit_event_background(
            &state,
            "admin.token.forbidden",
            Some(&payload.client_id),
            Some("Client is not authorized for management token issuance"),
        );
        return Err(AuthError::InsufficientRole);
    }

    state.clear_login_failures(&payload.client_id).await;

    let now = Utc::now().timestamp();
    let subject_prefix = "client";
    let access_claims = Claims {
        sub: format!("{}:{}", subject_prefix, payload.client_id),
        uid: None,
        iss: state.config.jwt_issuer.clone(),
        aud: "admin-backend".to_string(),
        scope: access_scope(subject_prefix, true),
        role: claim_role(subject_prefix, true),
        iat: now,
        exp: now + state.config.token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "access".to_string(),
    };

    let refresh_claims = Claims {
        sub: format!("{}:{}", subject_prefix, payload.client_id),
        uid: None,
        iss: state.config.jwt_issuer.clone(),
        aud: "admin-backend".to_string(),
        scope: vec!["refresh".into()],
        role: claim_role(subject_prefix, true),
        iat: now,
        exp: now + state.config.refresh_token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "refresh".to_string(),
    };

    let access_token = state.jwt_keys.sign_token(&access_claims)?;
    let refresh_token = state.jwt_keys.sign_token(&refresh_claims)?;

    crate::db::create_refresh_token(
        db,
        &refresh_claims.jti,
        &payload.client_id,
        &refresh_token,
        refresh_claims.exp,
    )
    .await
    .map_err(|_| AuthError::DatabaseError("Failed to create refresh token".to_string()))?;

    audit_event_background(
        &state,
        "admin.token.success",
        Some(&payload.client_id),
        Some("Management access token issued"),
    );

    Ok(Json(AuthBody::new(
        access_token,
        Some(refresh_token),
        state.config.token_expiry_seconds,
    )))
}

pub async fn auth_blacklist_token(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<BlacklistTokenRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    require_admin_scope(&claims)?;

    if let Some(db) = &state.db {
        crate::db::blacklist_token(
            db,
            &payload.token,
            payload.reason.as_deref(),
            payload
                .expires_at
                .unwrap_or_else(|| Utc::now().timestamp() + 3600), // 默认1小时
        )
        .await
        .map_err(|_| AuthError::DatabaseError("Failed to blacklist token".to_string()))?;
    } else {
        return Err(AuthError::DatabaseError(
            "Database not available".to_string(),
        ));
    }

    Ok(Json(json!({
        "message": "Token blacklisted successfully",
        "token": payload.token,
    })))
}

pub async fn auth_get_blacklisted_tokens(
    State(state): State<AppState>,
    claims: Claims,
) -> Result<Json<serde_json::Value>, AuthError> {
    require_admin_scope(&claims)?;

    if let Some(db) = &state.db {
        let tokens = crate::db::get_active_blacklisted_tokens(db)
            .await
            .map_err(|_| {
                AuthError::DatabaseError("Failed to get blacklisted tokens".to_string())
            })?;

        Ok(Json(json!({
            "blacklisted_tokens": tokens.into_iter().map(|(token_hash, expires_at)| {
                json!({
                    "token_hash": token_hash,
                    "expires_at": expires_at,
                })
            }).collect::<Vec<_>>()
        })))
    } else {
        Err(AuthError::DatabaseError(
            "Database not available".to_string(),
        ))
    }
}

pub async fn auth_get_audit_logs(
    State(state): State<AppState>,
    claims: Claims,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AuthError> {
    if !claims.has_scope("admin") {
        return Err(AuthError::Forbidden);
    }

    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    let offset = params
        .get("offset")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0)
        .max(0);

    if let Some(db) = &state.db {
        let logs = crate::db::list_audit_logs(db, limit, offset)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to query audit logs".to_string()))?;

        Ok(Json(json!({
            "success": true,
            "data": logs.into_iter().map(|(event_type, actor, detail, created_at)| {
                json!({
                    "event_type": event_type,
                    "actor": actor,
                    "detail": detail,
                    "created_at": created_at
                })
            }).collect::<Vec<_>>()
        })))
    } else {
        Err(AuthError::DatabaseError(
            "Database not available".to_string(),
        ))
    }
}

pub async fn auth_cleanup_audit_logs(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<CleanupAuditLogsRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    if !claims.has_scope("admin") {
        return Err(AuthError::Forbidden);
    }

    let retention_days = payload
        .retention_days
        .unwrap_or(state.config.audit_log_retention_days)
        .clamp(1, 3650);

    if let Some(db) = &state.db {
        let deleted = crate::db::cleanup_old_audit_logs(db, retention_days)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to cleanup audit logs".to_string()))?;

        Ok(Json(json!({
            "success": true,
            "retention_days": retention_days,
            "deleted": deleted
        })))
    } else {
        Err(AuthError::DatabaseError(
            "Database not available".to_string(),
        ))
    }
}

pub async fn auth_rotate_client_secret(
    State(state): State<AppState>,
    claims: Claims,
    Path(client_id): Path<String>,
    Json(payload): Json<RotateClientSecretRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    if !claims.has_scope("admin") {
        return Err(AuthError::Forbidden);
    }

    let db = state
        .db
        .as_deref()
        .ok_or_else(|| db_error("Database not available"))?;

    let provided_secret = payload
        .new_secret
        .as_deref()
        .filter(|secret| !secret.trim().is_empty());
    let generated_secret = provided_secret.is_none();
    let new_secret = provided_secret
        .map(str::to_string)
        .unwrap_or_else(|| format!("rot_{}", utils::generate_jti()));

    let updated = crate::db::rotate_client_secret(db, &client_id, &new_secret)
        .await
        .map_err(|_| AuthError::DatabaseError("Failed to rotate client secret".to_string()))?;

    if !updated {
        return Err(AuthError::NotFound);
    }

    let revoke_refresh_tokens = payload.revoke_refresh_tokens.unwrap_or(true);
    if revoke_refresh_tokens {
        crate::db::revoke_client_refresh_tokens(db, &client_id)
            .await
            .map_err(|_| {
                AuthError::DatabaseError("Failed to revoke existing refresh tokens".to_string())
            })?;
    }

    audit_event(
        &state,
        "admin.client.secret_rotated",
        Some(&claims.sub),
        Some(&format!(
            "client_id={}, revoke_refresh_tokens={}",
            client_id, revoke_refresh_tokens
        )),
    )
    .await;

    let mut response = json!({
        "success": true,
        "client_id": client_id,
        "revoke_refresh_tokens": revoke_refresh_tokens,
        "secret_generated": generated_secret,
    });
    if generated_secret {
        response["new_secret"] = json!(new_secret);
    }

    Ok(Json(response))
}

pub async fn auth_list_clients(
    State(state): State<AppState>,
    claims: Claims,
) -> Result<Json<serde_json::Value>, AuthError> {
    if !claims.has_scope("admin") {
        return Err(AuthError::Forbidden);
    }

    let db = state
        .db
        .as_deref()
        .ok_or_else(|| db_error("Database not available"))?;
    let clients = crate::db::list_clients_for_admin(db)
        .await
        .map_err(|_| AuthError::DatabaseError("Failed to list clients".to_string()))?;

    Ok(Json(json!({
        "success": true,
        "data": clients.into_iter().map(|(id, name, description, active, updated_at)| {
            json!({
                "id": id,
                "name": name,
                "description": description,
                "active": active,
                "updated_at": updated_at
            })
        }).collect::<Vec<_>>()
    })))
}

pub async fn auth_create_client(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<CreateClientRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    if !claims.has_scope("admin") {
        return Err(AuthError::Forbidden);
    }

    if payload.client_id.trim().is_empty()
        || payload.client_secret.trim().is_empty()
        || payload.name.trim().is_empty()
    {
        return Err(AuthError::MissingCredentials);
    }

    let db = state
        .db
        .as_deref()
        .ok_or_else(|| db_error("Database not available"))?;
    crate::db::create_management_client(
        db,
        &payload.client_id,
        &payload.client_secret,
        &payload.name,
        payload.description.as_deref(),
        payload.active.unwrap_or(true),
    )
    .await
    .map_err(|e| {
        if is_unique_violation(e.as_ref()) {
            AuthError::Conflict(format!(
                "Client '{}' already exists; choose a different client_id or update the existing client.",
                payload.client_id
            ))
        } else {
            AuthError::DatabaseError("Failed to create client".to_string())
        }
    })?;

    audit_event(
        &state,
        "admin.client.created",
        Some(&claims.sub),
        Some(&format!("client_id={}", payload.client_id)),
    )
    .await;

    Ok(Json(json!({
        "success": true,
        "client_id": payload.client_id,
    })))
}

pub async fn auth_update_client(
    State(state): State<AppState>,
    claims: Claims,
    Path(client_id): Path<String>,
    Json(payload): Json<UpdateClientRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    if !claims.has_scope("admin") {
        return Err(AuthError::Forbidden);
    }

    let db = state
        .db
        .as_deref()
        .ok_or_else(|| db_error("Database not available"))?;
    let updated = crate::db::update_management_client(
        db,
        &client_id,
        payload.client_secret.as_deref(),
        payload.name.as_deref(),
        payload.description.as_deref(),
        payload.active,
    )
    .await
    .map_err(|_| AuthError::DatabaseError("Failed to update client".to_string()))?;

    if !updated {
        return Err(AuthError::NotFound);
    }

    if payload.active == Some(false) {
        let _ = crate::db::revoke_client_refresh_tokens(db, &client_id).await;
    }

    audit_event(
        &state,
        "admin.client.updated",
        Some(&claims.sub),
        Some(&format!(
            "client_id={}, active={:?}",
            client_id, payload.active
        )),
    )
    .await;

    Ok(Json(json!({
        "success": true,
        "client_id": client_id,
    })))
}

pub async fn auth_me(claims: Claims) -> Result<Json<MeResponse>, AuthError> {
    Ok(Json(MeResponse {
        sub: claims.sub,
        uid: claims.uid,
        scope: claims.scope,
        role: claims.role,
        aud: claims.aud,
        exp: claims.exp,
        iss: claims.iss,
        jti: claims.jti,
    }))
}

pub async fn auth_introspect(
    State(state): State<AppState>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Json(payload): Json<IntrospectTokenRequest>,
) -> Json<TokenIntrospectResponse> {
    // Rate-limit per IP: 60 introspect calls per 60 seconds
    let client_ip = extract_client_ip(&headers, peer_addr, state.config.trust_proxy_headers);
    if !state
        .allow_auth_request(&format!("introspect:{}", client_ip), 60, 60)
        .await
    {
        return Json(TokenIntrospectResponse::inactive());
    }

    if payload.token.is_empty() {
        return Json(TokenIntrospectResponse::inactive());
    }

    match state.jwt_keys.decode_token(&payload.token) {
        Ok(claims) => {
            if let Some(db) = &state.db {
                if crate::db::is_token_blacklisted(db, &payload.token)
                    .await
                    .unwrap_or(false)
                {
                    return Json(TokenIntrospectResponse::inactive());
                }
            }

            Json(TokenIntrospectResponse::from_claims(&claims))
        }
        Err(_) => Json(TokenIntrospectResponse::inactive()),
    }
}
pub async fn auth_jwks(State(state): State<AppState>) -> Json<crate::models::JwksDocument> {
    Json(state.jwt_keys.jwks())
}

pub async fn keylo_configuration(State(state): State<AppState>) -> Json<KeyloConfiguration> {
    let issuer = state.config.jwt_issuer.clone();
    let base_url = state.config.server_url();

    Json(KeyloConfiguration {
        issuer,
        jwks_uri: format!("{}/.well-known/jwks.json", base_url),
        introspection_endpoint: format!("{}/v1/auth/introspect", base_url),
        service_token_endpoint: format!("{}/v1/service/token", base_url),
        service_introspection_endpoint: format!("{}/v1/service/introspect", base_url),
        user_token_endpoint: format!("{}/v1/auth/token", base_url),
        admin_token_endpoint: format!("{}/v1/admin/token", base_url),
        supported_token_types: vec![
            "access".to_string(),
            "refresh".to_string(),
            "service_access".to_string(),
        ],
        supported_claims: vec![
            "iss".to_string(),
            "sub".to_string(),
            "aud".to_string(),
            "exp".to_string(),
            "iat".to_string(),
            "jti".to_string(),
            "scope".to_string(),
            "role".to_string(),
            "token_type".to_string(),
            "uid".to_string(),
        ],
        supported_signing_algorithms: vec!["RS256".to_string()],
        supported_audiences: state.config.jwt_audiences.clone(),
        documentation_uri: format!("{}/docs/THIRD_PARTY_INTEGRATION.md", base_url),
    })
}

pub async fn auth_refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<AuthBody>, AuthError> {
    // Validate JWT token_type before touching the database to prevent
    // access tokens from being accepted as refresh tokens.
    let refresh_claims = state.jwt_keys.decode_token(&payload.refresh_token);
    match refresh_claims {
        Ok(ref c) if c.token_type != "refresh" => return Err(AuthError::TokenTypeInvalid),
        Err(_) => return Err(AuthError::InvalidToken),
        Ok(_) => {}
    }

    // Check if refresh token exists and is not revoked
    let client_id = if let Some(db) = &state.db {
        match crate::db::consume_refresh_token(db, &payload.refresh_token).await {
            Ok(Some((_id, client_id))) => client_id,
            _ => return Err(AuthError::InvalidToken),
        }
    } else {
        return Err(AuthError::DatabaseError(
            "Database not available".to_string(),
        ));
    };

    let now = Utc::now().timestamp();

    let is_admin_client = if let Some(db) = &state.db {
        match crate::db::get_client_auth_info(db, &client_id).await {
            Ok(Some((_, is_admin))) => is_admin,
            _ => false,
        }
    } else {
        false
    };

    if !is_admin_client {
        return Err(AuthError::InsufficientRole);
    }

    // Create new access token claims
    let access_claims = Claims {
        sub: format!("client:{}", client_id),
        uid: None,
        iss: state.config.jwt_issuer.clone(),
        aud: "admin-backend".to_string(),
        scope: access_scope("client", is_admin_client),
        role: claim_role("client", is_admin_client),
        iat: now,
        exp: now + state.config.token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "access".to_string(),
    };

    // Create new refresh token claims
    let new_refresh_claims = Claims {
        sub: format!("client:{}", client_id),
        uid: None,
        iss: state.config.jwt_issuer.clone(),
        aud: "admin-backend".to_string(),
        scope: vec!["refresh".into()],
        role: claim_role("client", is_admin_client),
        iat: now,
        exp: now + state.config.refresh_token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "refresh".to_string(),
    };

    // Create new tokens
    let access_token = state.jwt_keys.sign_token(&access_claims)?;

    let new_refresh_token = state.jwt_keys.sign_token(&new_refresh_claims)?;

    // Store new refresh token
    if let Some(db) = &state.db {
        crate::db::create_refresh_token(
            db,
            &new_refresh_claims.jti,
            &client_id,
            &new_refresh_token,
            new_refresh_claims.exp,
        )
        .await
        .map_err(|_| AuthError::DatabaseError("Failed to create refresh token".to_string()))?;
    }

    Ok(Json(AuthBody::new(
        access_token,
        Some(new_refresh_token),
        state.config.token_expiry_seconds,
    )))
}

pub async fn auth_logout(
    State(state): State<AppState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    claims: Claims,
) -> Result<Json<serde_json::Value>, AuthError> {
    // 将当前access token加入黑名单
    if let Some(db) = &state.db {
        let token = auth.token();
        crate::db::blacklist_token(db, token, Some("User logout"), claims.exp)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to blacklist token".to_string()))?;
    }

    tracing::info!("User {} logged out", claims.sub);
    audit_event(
        &state,
        "auth.logout",
        Some(&claims.sub),
        Some("User logged out and token blacklisted"),
    )
    .await;

    Ok(Json(json!({
        "message": "Successfully logged out",
        "sub": claims.sub,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_client_ip_ignores_forwarded_headers_when_untrusted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
        headers.insert("x-real-ip", "203.0.113.8".parse().unwrap());

        assert_eq!(
            extract_client_ip(
                &headers,
                Some(SocketAddr::from(([192, 0, 2, 10], 3000))),
                false
            ),
            "192.0.2.10"
        );
    }

    #[test]
    fn extract_client_ip_uses_forwarded_headers_when_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.7, 198.51.100.42".parse().unwrap(),
        );

        assert_eq!(extract_client_ip(&headers, None, true), "203.0.113.7");
    }

    #[test]
    fn extract_client_ip_rejects_invalid_forwarded_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
        headers.insert("x-real-ip", "also-bad".parse().unwrap());

        assert_eq!(
            extract_client_ip(
                &headers,
                Some(SocketAddr::from(([192, 0, 2, 10], 3000))),
                true
            ),
            "192.0.2.10"
        );
    }

    #[test]
    fn extract_client_ip_normalizes_ipv4_mapped_peer_addr() {
        let headers = HeaderMap::new();
        let peer = SocketAddr::new("::ffff:192.0.2.44".parse().unwrap(), 3000);

        assert_eq!(extract_client_ip(&headers, Some(peer), false), "192.0.2.44");
    }
}

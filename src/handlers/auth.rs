use crate::db::user::get_user_by_username;
use crate::errors::AuthError;
use crate::models::{
    AuthBody, AuthPayload, BlacklistTokenRequest, Claims, CleanupAuditLogsRequest, MeResponse,
    RefreshTokenRequest,
};
use crate::state::AppState;
use crate::utils;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::Json;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use bcrypt::verify;
use chrono::Utc;
use jsonwebtoken::{encode, Header};
use serde_json::json;
use std::collections::HashMap;

fn access_scope(subject_prefix: &str, is_admin_client: bool) -> Vec<String> {
    if subject_prefix == "client" && is_admin_client {
        vec!["read".into(), "write".into(), "admin".into()]
    } else {
        vec!["read".into(), "write".into()]
    }
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

fn extract_client_ip(headers: &HeaderMap) -> String {
    if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = value.split(',').next() {
            let ip = first.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }

    if let Some(value) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let ip = value.trim();
        if !ip.is_empty() {
            return ip.to_string();
        }
    }

    "unknown".to_string()
}

pub async fn auth_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<AuthPayload>,
) -> Result<Json<AuthBody>, AuthError> {
    // Check if the user sent the credentials
    if payload.client_id.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    let client_ip = extract_client_ip(&headers);
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

    let db = match &state.db {
        Some(db) => db,
        None => {
            return Err(AuthError::DatabaseError(
                "Database not available".to_string(),
            ))
        }
    };

    // First try to authenticate as a user
    let user_result = get_user_by_username(db, &payload.client_id).await;
    let (is_user_valid, _user_id) = match user_result {
        Ok(Some(user)) => {
            // Verify password
            if let Some(ref password_hash) = user.password_hash {
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

    let mut is_admin_client = false;
    let subject_prefix = if is_user_valid {
        "user"
    } else {
        // If user auth failed, try client auth (prefer DB)
        let client_valid = match crate::db::get_client_auth_info(db, &payload.client_id).await {
            Ok(Some((secret, is_admin))) => {
                is_admin_client = is_admin;
                secret == payload.client_secret
            }
            Ok(None) => state.validate_client(&payload.client_id, &payload.client_secret),
            Err(_) => return Err(AuthError::DatabaseError("Failed to get client".to_string())),
        };

        if !client_valid {
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
        "client"
    };

    state.clear_login_failures(&payload.client_id).await;
    audit_event(
        &state,
        "auth.token.success",
        Some(&payload.client_id),
        Some("Access token issued"),
    )
    .await;

    let now = Utc::now().timestamp();

    // Create access token claims
    let access_claims = Claims {
        sub: format!("{}:{}", subject_prefix, payload.client_id),
        iss: "keylo".to_string(),
        aud: "admin-backend".to_string(),
        scope: access_scope(subject_prefix, is_admin_client),
        iat: now,
        exp: now + state.config.token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "access".to_string(),
    };

    // Create refresh token claims
    // Create the authorization token
    let access_token = encode(&Header::default(), &access_claims, &state.jwt_keys.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    let refresh_token = if !is_user_valid {
        let refresh_claims = Claims {
            sub: format!("{}:{}", subject_prefix, payload.client_id),
            iss: "keylo".to_string(),
            aud: "admin-backend".to_string(),
            scope: vec!["refresh".into()],
            iat: now,
            exp: now + state.config.refresh_token_expiry_seconds,
            jti: utils::generate_jti(),
            token_type: "refresh".to_string(),
        };

        let token = encode(
            &Header::default(),
            &refresh_claims,
            &state.jwt_keys.encoding,
        )
        .map_err(|_| AuthError::TokenCreation)?;

        crate::db::create_refresh_token(
            db,
            &refresh_claims.jti,
            &payload.client_id,
            &token,
            refresh_claims.exp,
        )
        .await
        .map_err(|_| AuthError::DatabaseError("Failed to create refresh token".to_string()))?;

        Some(token)
    } else {
        None
    };

    // Send the authorized tokens
    Ok(Json(AuthBody::new(
        access_token,
        refresh_token,
        state.config.token_expiry_seconds,
    )))
}

pub async fn auth_blacklist_token(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<BlacklistTokenRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    // 只有管理员可以执行此操作
    if !claims.scope.contains(&"admin".to_string()) {
        return Err(AuthError::Forbidden);
    }

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
    // 只有管理员可以执行此操作
    if !claims.scope.contains(&"admin".to_string()) {
        return Err(AuthError::Forbidden);
    }

    if let Some(db) = &state.db {
        let tokens = crate::db::get_active_blacklisted_tokens(db)
            .await
            .map_err(|_| {
                AuthError::DatabaseError("Failed to get blacklisted tokens".to_string())
            })?;

        Ok(Json(json!({
            "blacklisted_tokens": tokens.into_iter().map(|(token, reason, expires_at)| {
                json!({
                    "token": token,
                    "reason": reason,
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
    if !claims.scope.contains(&"admin".to_string()) {
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
    if !claims.scope.contains(&"admin".to_string()) {
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

pub async fn auth_me(claims: Claims) -> Result<Json<MeResponse>, AuthError> {
    Ok(Json(MeResponse {
        sub: claims.sub,
        scope: claims.scope,
        aud: claims.aud,
        exp: claims.exp,
        iss: claims.iss,
        jti: claims.jti,
    }))
}

pub async fn auth_refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<AuthBody>, AuthError> {
    // Check if refresh token exists and is not revoked
    let (token_id, client_id) = if let Some(db) = &state.db {
        match crate::db::validate_refresh_token(db, &payload.refresh_token).await {
            Ok(Some((id, client_id))) => (id, client_id),
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

    // Create new access token claims
    let access_claims = Claims {
        sub: format!("client:{}", client_id),
        iss: "keylo".to_string(),
        aud: "admin-backend".to_string(),
        scope: access_scope("client", is_admin_client),
        iat: now,
        exp: now + state.config.token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "access".to_string(),
    };

    // Create new refresh token claims
    let new_refresh_claims = Claims {
        sub: format!("client:{}", client_id),
        iss: "keylo".to_string(),
        aud: "admin-backend".to_string(),
        scope: vec!["refresh".into()],
        iat: now,
        exp: now + state.config.refresh_token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "refresh".to_string(),
    };

    // Create new tokens
    let access_token = encode(&Header::default(), &access_claims, &state.jwt_keys.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    let new_refresh_token = encode(
        &Header::default(),
        &new_refresh_claims,
        &state.jwt_keys.encoding,
    )
    .map_err(|_| AuthError::TokenCreation)?;

    // Revoke old refresh token
    if let Some(db) = &state.db {
        crate::db::revoke_refresh_token(db, &token_id)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to revoke refresh token".to_string()))?;
    }

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

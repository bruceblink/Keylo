use crate::db::refresh_session::ConsumeRefreshSessionResult;
use crate::db::user::get_user_by_username;
use crate::errors::{is_unique_violation, AuthError};
use crate::models::{
    AuditLogExportQuery, AuthBody, AuthPayload, BlacklistTokenRequest, Claims,
    CleanupAuditLogsRequest, CreateClientRequest, IntrospectTokenRequest, KeyloConfiguration,
    MeResponse, OrganizationContextRequest, Principal, RefreshTokenRequest, RetireJwtKeyRequest,
    RotateClientSecretRequest, RotateJwtKeyRequest, TokenIntrospectResponse, UpdateClientRequest,
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
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path as FsPath;
use uuid::Uuid;

fn access_scope(_subject_prefix: &str, is_admin_client: bool) -> Vec<String> {
    if is_admin_client {
        vec!["read".into(), "write".into(), "admin".into()]
    } else {
        vec!["read".into(), "write".into()]
    }
}

const SENSITIVE_AUDIT_KEYS: &[&str] = &[
    "access_token",
    "refresh_token",
    "client_secret",
    "api_key",
    "password",
    "recovery_code",
    "totp_code",
    "verifier",
];

/// Redact credentials from exported details while preserving operational context.
fn redact_audit_detail(detail: Option<String>) -> Option<String> {
    detail.map(|value| {
        if let Ok(mut json_value) = serde_json::from_str::<Value>(&value) {
            redact_audit_json_value(&mut json_value);
            return json_value.to_string();
        }

        value
            .split_whitespace()
            .map(|part| {
                let lower = part.to_ascii_lowercase();
                let is_sensitive = SENSITIVE_AUDIT_KEYS.iter().any(|key| {
                    lower.starts_with(&format!("{key}=")) || lower.starts_with(&format!("{key}:"))
                });
                if is_sensitive {
                    part.split_once(['=', ':'])
                        .map(|(key, _)| format!("{key}=[REDACTED]"))
                        .unwrap_or_else(|| "[REDACTED]".to_string())
                } else if part.len() >= 24 && part.matches('.').count() == 2 {
                    "[REDACTED_TOKEN]".to_string()
                } else {
                    part.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    })
}

fn redact_audit_json_value(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            for (key, child) in fields.iter_mut() {
                if SENSITIVE_AUDIT_KEYS
                    .iter()
                    .any(|sensitive| key.eq_ignore_ascii_case(sensitive))
                {
                    *child = Value::String("[REDACTED]".to_string());
                } else {
                    redact_audit_json_value(child);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_audit_json_value),
        _ => {}
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
    crate::db::user_is_platform_admin(db, user_id)
        .await
        .unwrap_or(false)
}

/// Resolves an optional organization requested at password login into a live
/// membership-backed session scope. A caller-supplied identifier is never used
/// until this check confirms that the human Principal can currently enter it.
async fn resolve_requested_organization_session_scope(
    db: &sqlx::PgPool,
    requested_organization_id: Option<&str>,
    principal: &Principal,
) -> Result<Option<String>, AuthError> {
    let Some(organization_id) = requested_organization_id else {
        return Ok(None);
    };
    let organization_id = organization_id.trim();
    if organization_id.is_empty() {
        return Err(AuthError::InvalidRequest(
            "organization_id must not be empty".to_string(),
        ));
    }

    let membership =
        crate::db::get_active_organization_membership(db, organization_id, &principal.id)
            .await
            .map_err(|_| {
                AuthError::DatabaseError("Failed to resolve organization membership".to_string())
            })?;

    membership
        .map(|membership| Some(membership.organization_id))
        .ok_or(AuthError::Forbidden)
}

/// Preserves a generic authorization failure when a lifecycle change wins the
/// race against scoped-session creation, while retaining database diagnostics
/// for every other persistence failure.
fn map_refresh_session_creation_error(error: anyhow::Error) -> AuthError {
    let message = error.to_string();
    if message == "organization_session_context_inactive" {
        AuthError::Forbidden
    } else {
        AuthError::DatabaseError("Failed to create refresh session".to_string())
    }
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

async fn access_claims_for_principal(
    state: &AppState,
    db: &sqlx::PgPool,
    principal: &Principal,
    now: i64,
    jti: String,
) -> Result<Claims, AuthError> {
    match principal.principal_type.as_str() {
        "user" => {
            let user = crate::db::user::get_user_by_id(db, &principal.ref_id)
                .await
                .map_err(|_| AuthError::DatabaseError("Failed to get user".to_string()))?
                .filter(|user| user.active)
                .ok_or(AuthError::InvalidToken)?;
            let is_admin_user = is_user_admin(db, &user.id).await;
            Ok(Claims {
                sub: format!("user:{}", user.username),
                uid: Some(user.id),
                principal_id: Some(principal.id.clone()),
                principal_type: Some("user".to_string()),
                organization_id: None,
                customer_support_grant_id: None,
                iss: state.config.jwt_issuer.clone(),
                aud: "admin-backend".to_string(),
                scope: access_scope("user", is_admin_user),
                role: claim_role("user", is_admin_user),
                iat: now,
                exp: now + state.config.token_expiry_seconds,
                jti,
                token_type: "access".to_string(),
            })
        }
        "client" => {
            let is_admin_client = match crate::db::get_client_auth_info(db, &principal.ref_id).await
            {
                Ok(Some((_, is_admin))) => is_admin,
                _ => false,
            };
            if !is_admin_client {
                return Err(AuthError::InsufficientRole);
            }
            Ok(Claims {
                sub: format!("client:{}", principal.ref_id),
                uid: None,
                principal_id: Some(principal.id.clone()),
                principal_type: Some("client".to_string()),
                organization_id: None,
                customer_support_grant_id: None,
                iss: state.config.jwt_issuer.clone(),
                aud: "admin-backend".to_string(),
                scope: access_scope("client", true),
                role: claim_role("client", true),
                iat: now,
                exp: now + state.config.token_expiry_seconds,
                jti,
                token_type: "access".to_string(),
            })
        }
        _ => Err(AuthError::TokenTypeInvalid),
    }
}

async fn enforce_refresh_session_policy(
    state: &AppState,
    db: &sqlx::PgPool,
    principal: &Principal,
    force_takeover: bool,
) -> Result<(), AuthError> {
    let applies = match state.config.session_policy.as_str() {
        "multi_session" => false,
        "single_user_session" => principal.principal_type == "user",
        "single_principal_session" => true,
        _ => false,
    };

    if !applies {
        return Ok(());
    }

    if !crate::db::has_active_refresh_session_for_principal(db, &principal.id)
        .await
        .map_err(|_| AuthError::DatabaseError("Failed to check refresh sessions".to_string()))?
    {
        return Ok(());
    }

    if !force_takeover {
        return Err(AuthError::Conflict("active_session_exists".to_string()));
    }

    crate::db::revoke_principal_refresh_sessions(db, &principal.id, Some("session_takeover"))
        .await
        .map_err(|_| AuthError::DatabaseError("Failed to revoke refresh sessions".to_string()))?;
    audit_event(
        state,
        "auth.session.takeover",
        Some(&principal.subject),
        Some(&format!("principal_id={}", principal.id)),
    )
    .await;

    Ok(())
}

/// Issue Keylo access and refresh tokens for an already verified external user and persist its session.
pub async fn issue_external_user_session(
    state: &AppState,
    db: &sqlx::PgPool,
    user: &crate::models::User,
    session_client_id: &str,
    organization_id: Option<&str>,
) -> Result<AuthBody, AuthError> {
    if !user.active {
        return Err(AuthError::Forbidden);
    }

    let principal = crate::db::ensure_user_principal(db, &user.id)
        .await
        .map_err(|_| AuthError::DatabaseError("Failed to resolve user principal".to_string()))?
        .ok_or(AuthError::InvalidToken)?;
    if let Some(organization_id) = organization_id {
        crate::db::get_active_organization_membership(db, organization_id, &principal.id)
            .await
            .map_err(|_| {
                AuthError::DatabaseError(
                    "Failed to validate external login organization".to_string(),
                )
            })?
            .ok_or(AuthError::Forbidden)?;
    }
    enforce_refresh_session_policy(state, db, &principal, false).await?;

    let now = Utc::now().timestamp();
    let is_admin_user = is_user_admin(db, &user.id).await;
    let access_claims = Claims {
        sub: format!("user:{}", user.username),
        uid: Some(user.id.clone()),
        principal_id: Some(principal.id.clone()),
        principal_type: Some("user".to_string()),
        organization_id: organization_id.map(str::to_string),
        customer_support_grant_id: None,
        iss: state.config.jwt_issuer.clone(),
        aud: "admin-backend".to_string(),
        scope: access_scope("user", is_admin_user),
        role: claim_role("user", is_admin_user),
        iat: now,
        exp: now + state.config.token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "access".to_string(),
    };
    let refresh_claims = Claims {
        sub: access_claims.sub.clone(),
        uid: access_claims.uid.clone(),
        principal_id: Some(principal.id.clone()),
        principal_type: Some("user".to_string()),
        organization_id: organization_id.map(str::to_string),
        customer_support_grant_id: None,
        iss: state.config.jwt_issuer.clone(),
        aud: "admin-backend".to_string(),
        scope: vec!["refresh".into()],
        // Refresh tokens are not authorization artifacts and never carry roles.
        role: Vec::new(),
        iat: now,
        exp: now + state.config.refresh_token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "refresh".to_string(),
    };
    let access_token = state.jwt_keys.sign_token(&access_claims)?;
    let refresh_token = state.jwt_keys.sign_token(&refresh_claims)?;
    let session_id = utils::generate_jti();
    crate::db::create_refresh_session(
        db,
        crate::db::CreateRefreshSessionParams {
            session_id: &session_id,
            principal_id: &principal.id,
            client_id: session_client_id,
            organization_id,
            refresh_token_id: &refresh_claims.jti,
            refresh_token: &refresh_token,
            access_jti: &access_claims.jti,
            login_ip: None,
            user_agent: None,
            expires_at: refresh_claims.exp,
        },
    )
    .await
    .map_err(|_| AuthError::DatabaseError("Failed to create refresh session".to_string()))?;
    audit_event(
        state,
        "auth.external_login.success",
        Some(&user.id),
        Some(&format!(
            "session_id={}; client_id={}",
            session_id, session_client_id
        )),
    )
    .await;

    Ok(AuthBody::new(
        access_token,
        Some(refresh_token),
        state.config.token_expiry_seconds,
    ))
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

fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(512).collect())
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
    let user_agent = extract_user_agent(&headers);
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
        state.runtime_metrics.rate_limit_rejection_observed();
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
        state.runtime_metrics.rate_limit_rejection_observed();
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

    let now = Utc::now().timestamp();
    let subject_prefix = "user";
    let is_admin_user = if let Some(user_id) = user_id.as_deref() {
        is_user_admin(db, user_id).await
    } else {
        false
    };

    let principal = match user_id.as_deref() {
        Some(user_id) => crate::db::ensure_user_principal(db, user_id)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to resolve principal".to_string()))?,
        None => None,
    };
    let organization_id = match principal.as_ref() {
        Some(principal) => {
            resolve_requested_organization_session_scope(
                db,
                payload.organization_id.as_deref(),
                principal,
            )
            .await?
        }
        None if payload.organization_id.is_some() => return Err(AuthError::InvalidToken),
        None => None,
    };
    if let Some(principal) = principal.as_ref() {
        enforce_refresh_session_policy(&state, db, principal, payload.force.unwrap_or(false))
            .await?;
    }

    state.clear_login_failures(&payload.client_id).await;
    let audit_detail = organization_id.as_deref().map_or_else(
        || "Access token issued".to_string(),
        |organization_id| format!("Access token issued; organization_id={organization_id}"),
    );
    audit_event(
        &state,
        "auth.token.success",
        Some(&payload.client_id),
        Some(&audit_detail),
    )
    .await;

    // Create access token claims
    let access_claims = Claims {
        sub: format!("{}:{}", subject_prefix, payload.client_id),
        uid: user_id.clone(),
        principal_id: principal.as_ref().map(|value| value.id.clone()),
        principal_type: Some("user".to_string()),
        organization_id: organization_id.clone(),
        customer_support_grant_id: None,
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

    let refresh_claims = Claims {
        sub: format!("{}:{}", subject_prefix, payload.client_id),
        uid: user_id.clone(),
        principal_id: principal.as_ref().map(|value| value.id.clone()),
        principal_type: Some("user".to_string()),
        organization_id: organization_id.clone(),
        customer_support_grant_id: None,
        iss: state.config.jwt_issuer.clone(),
        aud: "admin-backend".to_string(),
        scope: vec!["refresh".into()],
        // Refresh tokens are not authorization artifacts and never carry roles.
        role: Vec::new(),
        iat: now,
        exp: now + state.config.refresh_token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "refresh".to_string(),
    };
    let refresh_token = state.jwt_keys.sign_token(&refresh_claims)?;
    if let Some(principal) = principal.as_ref() {
        let session_id = utils::generate_jti();
        let refresh_client_id = format!("user:{}", payload.client_id);
        crate::db::create_refresh_session(
            db,
            crate::db::CreateRefreshSessionParams {
                session_id: &session_id,
                principal_id: &principal.id,
                client_id: &refresh_client_id,
                organization_id: organization_id.as_deref(),
                refresh_token_id: &refresh_claims.jti,
                refresh_token: &refresh_token,
                access_jti: &access_claims.jti,
                login_ip: Some(&client_ip),
                user_agent: user_agent.as_deref(),
                expires_at: refresh_claims.exp,
            },
        )
        .await
        .map_err(map_refresh_session_creation_error)?;
    }

    // Send the authorized tokens
    Ok(Json(AuthBody::new(
        access_token,
        Some(refresh_token),
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
    if payload.organization_id.is_some() {
        return Err(AuthError::InvalidRequest(
            "organization_id is only supported by /v1/auth/token".to_string(),
        ));
    }

    let client_ip = extract_client_ip(&headers, peer_addr, state.config.trust_proxy_headers);
    let user_agent = extract_user_agent(&headers);
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
        state.runtime_metrics.rate_limit_rejection_observed();
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
    let principal = crate::db::ensure_client_principal(db, &payload.client_id)
        .await
        .map_err(|_| AuthError::DatabaseError("Failed to resolve principal".to_string()))?;
    if let Some(principal) = principal.as_ref() {
        enforce_refresh_session_policy(&state, db, principal, payload.force.unwrap_or(false))
            .await?;
    }
    let access_claims = Claims {
        sub: format!("{}:{}", subject_prefix, payload.client_id),
        uid: None,
        principal_id: principal.as_ref().map(|value| value.id.clone()),
        principal_type: Some("client".to_string()),
        organization_id: None,
        customer_support_grant_id: None,
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
        principal_id: principal.as_ref().map(|value| value.id.clone()),
        principal_type: Some("client".to_string()),
        organization_id: None,
        customer_support_grant_id: None,
        iss: state.config.jwt_issuer.clone(),
        aud: "admin-backend".to_string(),
        scope: vec!["refresh".into()],
        // Refresh tokens are not authorization artifacts and never carry roles.
        role: Vec::new(),
        iat: now,
        exp: now + state.config.refresh_token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "refresh".to_string(),
    };

    let access_token = state.jwt_keys.sign_token(&access_claims)?;
    let refresh_token = state.jwt_keys.sign_token(&refresh_claims)?;

    if let Some(principal) = principal.as_ref() {
        let session_id = utils::generate_jti();
        crate::db::create_refresh_session(
            db,
            crate::db::CreateRefreshSessionParams {
                session_id: &session_id,
                principal_id: &principal.id,
                client_id: &payload.client_id,
                organization_id: None,
                refresh_token_id: &refresh_claims.jti,
                refresh_token: &refresh_token,
                access_jti: &access_claims.jti,
                login_ip: Some(&client_ip),
                user_agent: user_agent.as_deref(),
                expires_at: refresh_claims.exp,
            },
        )
        .await
        .map_err(|_| AuthError::DatabaseError("Failed to create refresh session".to_string()))?;
    }

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

pub async fn auth_export_audit_logs(
    State(state): State<AppState>,
    claims: Claims,
    Query(params): Query<AuditLogExportQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    if !claims.has_scope("admin") {
        return Err(AuthError::Forbidden);
    }

    if let Some(cursor) = params.cursor.as_deref() {
        let (micros, id) = cursor
            .rsplit_once(':')
            .ok_or_else(|| AuthError::InvalidRequest("invalid audit export cursor".to_string()))?;
        if micros.parse::<i64>().is_err() || id.is_empty() {
            return Err(AuthError::InvalidRequest(
                "invalid audit export cursor".to_string(),
            ));
        }
    }

    let limit = params.limit.unwrap_or(100).clamp(1, 200);
    let db = state
        .db
        .as_ref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let page = crate::db::list_audit_log_export(
        db,
        limit,
        params.event_type.as_deref(),
        params.cursor.as_deref(),
    )
    .await
    .map_err(|_| AuthError::DatabaseError("Failed to export audit logs".to_string()))?;

    let data = page
        .entries
        .into_iter()
        .map(|entry| {
            json!({
                "id": entry.id,
                "event_type": entry.event_type,
                "actor": entry.actor,
                "detail": redact_audit_detail(entry.detail),
                "created_at": entry.created_at,
            })
        })
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "success": true,
        "data": data,
        "next_cursor": page.next_cursor,
        "dedupe_key": "id"
    })))
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
        crate::db::revoke_client_refresh_sessions(db, &client_id, Some("client_secret_rotated"))
            .await
            .map_err(|_| {
                AuthError::DatabaseError("Failed to revoke existing refresh sessions".to_string())
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
        let _ = crate::db::revoke_client_refresh_sessions(db, &client_id, Some("client_disabled"))
            .await;
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
        principal_id: claims.principal_id,
        principal_type: claims.principal_type,
        organization_id: claims.organization_id,
        scope: claims.scope,
        role: claims.role,
        aud: claims.aud,
        exp: claims.exp,
        iss: claims.iss,
        jti: claims.jti,
    }))
}

/// Re-issues a short-lived access token after verifying the caller's active
/// membership. The signed claim, rather than a request header, is the only
/// organization context consumed by delegated organization APIs.
pub async fn auth_select_organization_context(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<OrganizationContextRequest>,
) -> Result<Json<AuthBody>, AuthError> {
    if claims.token_type != "access" || claims.principal_type.as_deref() != Some("user") {
        return Err(AuthError::Forbidden);
    }
    let user_id = claims.uid.as_deref().ok_or(AuthError::InvalidToken)?;
    let db = require_db(&state)?;
    let principal = if let Some(principal_id) = claims.principal_id.as_deref() {
        crate::db::get_principal_by_id(db, principal_id)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to resolve principal".to_string()))?
    } else {
        crate::db::get_principal_by_ref(db, "user", user_id)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to resolve principal".to_string()))?
    };
    let principal = principal.ok_or(AuthError::InvalidToken)?;
    if principal.principal_type != "user" || principal.ref_id != user_id || !principal.active {
        return Err(AuthError::InvalidToken);
    }
    let membership =
        crate::db::get_active_organization_membership(db, &payload.organization_id, &principal.id)
            .await
            .map_err(|_| {
                AuthError::DatabaseError("Failed to resolve organization membership".to_string())
            })?
            .ok_or(AuthError::Forbidden)?;

    let now = Utc::now().timestamp();
    let mut context_claims = claims;
    context_claims.organization_id = Some(membership.organization_id.clone());
    context_claims.iat = now;
    context_claims.exp = now + state.config.token_expiry_seconds;
    context_claims.jti = utils::generate_jti();
    context_claims.token_type = "access".to_string();
    let access_token = state.jwt_keys.sign_token(&context_claims)?;
    audit_event(
        &state,
        "organization.context.selected",
        Some(&principal.subject),
        Some(&format!("organization_id={}", membership.organization_id)),
    )
    .await;

    Ok(Json(AuthBody::new(
        access_token,
        None,
        state.config.token_expiry_seconds,
    )))
}

/// Resolve the current database state for a token so introspection does not advertise disabled identities as active.
async fn introspected_claims_are_active(db: &sqlx::PgPool, claims: &Claims) -> bool {
    // Support tokens deliberately have no organization membership. Their live
    // grant is the only tenant boundary, so applying the normal membership
    // check below would incorrectly report every valid support token inactive.
    if claims.token_type == "customer_support_access" {
        let (Some(grant_id), Some(principal_id), Some(organization_id), Some(user_id)) = (
            claims.customer_support_grant_id.as_deref(),
            claims.principal_id.as_deref(),
            claims.organization_id.as_deref(),
            claims.uid.as_deref(),
        ) else {
            return false;
        };
        if claims.principal_type.as_deref() != Some("user")
            || !claims.has_role(crate::models::CUSTOMER_SUPPORT_ROLE_NAME)
            || !claims.has_audience("admin-backend")
        {
            return false;
        }
        let Ok(Some(principal)) = crate::db::get_principal_by_id(db, principal_id).await else {
            return false;
        };
        if !principal.active || principal.principal_type != "user" || principal.ref_id != user_id {
            return false;
        }
        return matches!(
            crate::db::get_live_customer_support_access_context(
                db,
                grant_id,
                principal_id,
                organization_id,
            )
            .await,
            Ok(decision) if decision.allowed
        );
    }
    if let Some(organization_id) = claims.organization_id.as_deref() {
        if claims.principal_type.as_deref() != Some("user") {
            return false;
        }
        let Some(principal_id) = claims.principal_id.as_deref() else {
            return false;
        };
        if !matches!(
            crate::db::get_active_organization_membership(db, organization_id, principal_id).await,
            Ok(Some(_))
        ) {
            return false;
        }
    }
    let advertises_platform_admin = claims.has_role("admin") || claims.has_scope("admin");
    if let Some(principal_id) = claims.principal_id.as_deref() {
        let Ok(Some(principal)) = crate::db::get_principal_by_id(db, principal_id).await else {
            return false;
        };
        if !principal.active {
            return false;
        }
        return match principal.principal_type.as_str() {
            "user" if advertises_platform_admin => {
                crate::db::user_is_platform_admin(db, &principal.ref_id)
                    .await
                    .unwrap_or(false)
            }
            "client" if advertises_platform_admin => {
                matches!(
                    crate::db::get_client_auth_info(db, &principal.ref_id).await,
                    Ok(Some((_, true)))
                )
            }
            _ => true,
        };
    }
    if claims.principal_type.as_deref() == Some("user") {
        if let Some(user_id) = claims.uid.as_deref() {
            let Ok(Some(user)) = crate::db::get_user_by_id(db, user_id).await else {
                return false;
            };
            if !user.active {
                return false;
            }
            if advertises_platform_admin {
                return crate::db::user_is_platform_admin(db, user_id)
                    .await
                    .unwrap_or(false);
            }
            return true;
        }
    }
    // Keep pre-Principal client tokens compatible; newer tokens always carry principal_id.
    true
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
                    .unwrap_or(true)
                    || !introspected_claims_are_active(db, &claims).await
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

/// Persist a rotated key through a sibling temporary file so readers never see partial PEM data.
fn persist_rotation_file(path: &str, contents: &str, private_key: bool) -> Result<(), AuthError> {
    let target = FsPath::new(path);
    if let Some(parent) = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| {
            AuthError::InternalServerError(format!("failed to create key directory: {error}"))
        })?;
    }
    let temporary = FsPath::new(&format!("{path}.next")).to_path_buf();
    fs::write(&temporary, contents).map_err(|error| {
        AuthError::InternalServerError(format!("failed to persist rotated key: {error}"))
    })?;
    if private_key {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).map_err(
                |error| {
                    AuthError::InternalServerError(format!(
                        "failed to protect rotated private key: {error}"
                    ))
                },
            )?;
        }
    }
    if target.exists() {
        fs::remove_file(target).map_err(|error| {
            AuthError::InternalServerError(format!("failed to replace rotated key: {error}"))
        })?;
    }
    fs::rename(&temporary, target).map_err(|error| {
        AuthError::InternalServerError(format!("failed to activate rotated key: {error}"))
    })?;
    Ok(())
}

/// Remove a retired key file while treating an already absent file as success.
fn remove_rotation_file(path: &str) -> Result<(), AuthError> {
    let target = FsPath::new(path);
    if target.exists() {
        fs::remove_file(target).map_err(|error| {
            AuthError::InternalServerError(format!("failed to retire persisted key: {error}"))
        })?;
    }
    Ok(())
}

/// Record a key lifecycle event without including private key material in the audit detail.
async fn audit_jwt_key_event(
    state: &AppState,
    event_type: &str,
    actor: &str,
    detail: &str,
) -> Result<(), AuthError> {
    let Some(db) = state.db.as_deref() else {
        return Err(AuthError::DatabaseError(
            "Database not available".to_string(),
        ));
    };
    crate::db::create_audit_log(db, event_type, Some(actor), Some(detail))
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))
}

/// Rotate the signing key while retaining the previous private/public pair for rollback.
pub async fn auth_rotate_jwt_key(
    claims: Claims,
    State(state): State<AppState>,
    Json(request): Json<RotateJwtKeyRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let key_id = request.key_id.unwrap_or_else(|| {
        format!(
            "{}-{}",
            state.jwt_keys.active_key_id(),
            Uuid::new_v4().simple()
        )
    });
    if key_id.len() > 128
        || key_id.is_empty()
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(AuthError::InvalidRequest(
            "key_id must contain only ASCII letters, digits, '.', '_' or '-' and be at most 128 characters"
                .to_string(),
        ));
    }
    let overlap_seconds = request
        .overlap_seconds
        .unwrap_or(state.config.jwt_key_overlap_seconds);
    if !(1..=2_592_000).contains(&overlap_seconds) {
        return Err(AuthError::InvalidRequest(
            "overlap_seconds must be between 1 and 2592000".to_string(),
        ));
    }
    let old_key_id = state.jwt_keys.active_key_id();
    let (old_private, old_public) = state.jwt_keys.active_key_material();
    let (new_private, new_public) =
        crate::config::generate_rsa_key_pair().map_err(AuthError::InternalServerError)?;

    persist_rotation_file(
        &state.config.jwt_passive_private_key_path,
        &old_private,
        true,
    )?;
    persist_rotation_file(
        &state.config.jwt_passive_public_key_path,
        &old_public,
        false,
    )?;
    persist_rotation_file(&state.config.jwt_passive_key_id_path, &old_key_id, false)?;
    persist_rotation_file(&state.config.jwt_private_key_path, &new_private, true)?;
    persist_rotation_file(&state.config.jwt_public_key_path, &new_public, false)?;
    persist_rotation_file(&state.config.jwt_key_id_path, &key_id, false)?;
    state
        .jwt_keys
        .rotate(&key_id, &new_private, &new_public, overlap_seconds)
        .map_err(AuthError::InternalServerError)?;

    let detail = format!(
        "active_key_id={key_id}; passive_key_id={old_key_id}; overlap_seconds={overlap_seconds}"
    );
    audit_jwt_key_event(&state, "jwt_signing_key.rotated", &claims.sub, &detail).await?;
    Ok(Json(json!({
        "success": true,
        "data": {
            "active_key_id": state.jwt_keys.active_key_id(),
            "passive_key_ids": state.jwt_keys.passive_key_ids(),
            "overlap_seconds": overlap_seconds
        }
    })))
}

/// Retire a passive key early and remove its persisted verification material.
pub async fn auth_retire_jwt_key(
    claims: Claims,
    State(state): State<AppState>,
    Json(request): Json<RetireJwtKeyRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    if !state.jwt_keys.retire_passive(&request.key_id) {
        return Err(AuthError::NotFound);
    }
    remove_rotation_file(&state.config.jwt_passive_private_key_path)?;
    remove_rotation_file(&state.config.jwt_passive_public_key_path)?;
    remove_rotation_file(&state.config.jwt_passive_key_id_path)?;
    audit_jwt_key_event(
        &state,
        "jwt_signing_key.retired",
        &claims.sub,
        &format!("passive_key_id={}", request.key_id),
    )
    .await?;
    Ok(Json(json!({
        "success": true,
        "data": {"active_key_id": state.jwt_keys.active_key_id(), "passive_key_ids": state.jwt_keys.passive_key_ids()}
    })))
}

/// Roll back to a retained passive key while keeping the current signer in overlap.
pub async fn auth_rollback_jwt_key(
    claims: Claims,
    State(state): State<AppState>,
    Json(request): Json<RetireJwtKeyRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let (passive_private, passive_public) = state
        .jwt_keys
        .passive_key_material(&request.key_id)
        .ok_or_else(|| {
            AuthError::Conflict("passive key private material is unavailable".to_string())
        })?;
    let (active_private, active_public) = state.jwt_keys.active_key_material();
    let active_key_id = state.jwt_keys.active_key_id();
    let overlap_seconds = state.config.jwt_key_overlap_seconds;
    persist_rotation_file(
        &state.config.jwt_passive_private_key_path,
        &active_private,
        true,
    )?;
    persist_rotation_file(
        &state.config.jwt_passive_public_key_path,
        &active_public,
        false,
    )?;
    persist_rotation_file(&state.config.jwt_passive_key_id_path, &active_key_id, false)?;
    persist_rotation_file(&state.config.jwt_private_key_path, &passive_private, true)?;
    persist_rotation_file(&state.config.jwt_public_key_path, &passive_public, false)?;
    persist_rotation_file(&state.config.jwt_key_id_path, &request.key_id, false)?;
    state
        .jwt_keys
        .rollback(&request.key_id, overlap_seconds)
        .map_err(AuthError::InternalServerError)?;
    audit_jwt_key_event(
        &state,
        "jwt_signing_key.rollback",
        &claims.sub,
        &format!(
            "active_key_id={}; passive_key_id={}; overlap_seconds={overlap_seconds}",
            request.key_id, active_key_id
        ),
    )
    .await?;
    Ok(Json(json!({
        "success": true,
        "data": {"active_key_id": state.jwt_keys.active_key_id(), "passive_key_ids": state.jwt_keys.passive_key_ids()}
    })))
}

pub async fn keylo_configuration(State(state): State<AppState>) -> Json<KeyloConfiguration> {
    // Keep JWT issuer semantics separate from the public origin used to build copy-pasteable URLs.
    let issuer = state.config.jwt_issuer.clone();
    let base_url = state.config.oidc_issuer();

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
            "customer_support_access".to_string(),
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
            "principal_id".to_string(),
            "principal_type".to_string(),
            "organization_id".to_string(),
            "customer_support_grant_id".to_string(),
        ],
        supported_signing_algorithms: vec!["RS256".to_string()],
        supported_audiences: state.config.jwt_audiences.clone(),
        documentation_uri: format!("{}/docs/integrations/THIRD_PARTY_INTEGRATION.md", base_url),
    })
}

pub async fn auth_refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<AuthBody>, AuthError> {
    // Validate JWT token_type before touching the database to prevent
    // access tokens from being accepted as refresh tokens.
    let refresh_claims = state.jwt_keys.decode_token(&payload.refresh_token);
    let refresh_claims = match refresh_claims {
        Ok(ref c) if c.token_type != "refresh" => return Err(AuthError::TokenTypeInvalid),
        Err(_) => return Err(AuthError::InvalidToken),
        Ok(claims) => claims,
    };

    let db = require_db(&state)?;
    if let Some(organization_id) = refresh_claims.organization_id.as_deref() {
        if refresh_claims.principal_type.as_deref() != Some("user") {
            return Err(AuthError::InvalidToken);
        }
        let principal_id = refresh_claims
            .principal_id
            .as_deref()
            .ok_or(AuthError::InvalidToken)?;
        let active_membership =
            crate::db::get_active_organization_membership(db, organization_id, principal_id)
                .await
                .map_err(|_| {
                    AuthError::DatabaseError(
                        "Failed to resolve organization membership".to_string(),
                    )
                })?;
        if active_membership.is_none() {
            let _ = crate::db::revoke_refresh_session_by_token(
                db,
                &payload.refresh_token,
                Some("organization_membership_inactive"),
            )
            .await;
            return Err(AuthError::InvalidToken);
        }
    }
    let now = Utc::now().timestamp();
    let access_jti = utils::generate_jti();
    let refresh_jti = utils::generate_jti();
    let new_refresh_claims = Claims {
        sub: refresh_claims.sub.clone(),
        uid: refresh_claims.uid.clone(),
        principal_id: refresh_claims.principal_id.clone(),
        principal_type: refresh_claims.principal_type.clone(),
        organization_id: refresh_claims.organization_id.clone(),
        customer_support_grant_id: None,
        iss: state.config.jwt_issuer.clone(),
        aud: refresh_claims.aud.clone(),
        scope: vec!["refresh".into()],
        // Recompute access authority from live database state after rotation.
        role: Vec::new(),
        iat: now,
        exp: refresh_claims.exp,
        jti: refresh_jti.clone(),
        token_type: "refresh".to_string(),
    };
    let new_refresh_token = state.jwt_keys.sign_token(&new_refresh_claims)?;

    match crate::db::consume_and_rotate_refresh_session(
        db,
        &payload.refresh_token,
        refresh_claims.organization_id.as_deref(),
        &refresh_jti,
        &new_refresh_token,
        &access_jti,
    )
    .await
    .map_err(|_| AuthError::DatabaseError("Failed to consume refresh session".to_string()))?
    {
        ConsumeRefreshSessionResult::Consumed(session) => {
            let principal = crate::db::get_principal_by_id(db, &session.principal_id)
                .await
                .map_err(|_| AuthError::DatabaseError("Failed to get principal".to_string()))?
                .filter(|principal| principal.active)
                .ok_or(AuthError::InvalidToken)?;
            let mut access_claims =
                access_claims_for_principal(&state, db, &principal, now, access_jti).await?;
            access_claims.organization_id = refresh_claims.organization_id.clone();
            let access_token = state.jwt_keys.sign_token(&access_claims)?;

            audit_event(
                &state,
                "auth.refresh.success",
                Some(&principal.subject),
                Some(&format!("session_id={}", session.session_id)),
            )
            .await;

            return Ok(Json(AuthBody::new(
                access_token,
                Some(new_refresh_token),
                state.config.token_expiry_seconds,
            )));
        }
        ConsumeRefreshSessionResult::Replayed { session_id } => {
            state.runtime_metrics.refresh_replay_observed();
            audit_event(
                &state,
                "auth.refresh.replay",
                Some(refresh_claims.sub.as_str()),
                Some(&format!("session_id={}", session_id)),
            )
            .await;
            return Err(AuthError::InvalidToken);
        }
        ConsumeRefreshSessionResult::OrganizationScopeMismatch => {
            audit_event(
                &state,
                "auth.refresh.organization_scope_mismatch",
                Some(refresh_claims.sub.as_str()),
                Some("Refresh session organization scope does not match token"),
            )
            .await;
            return Err(AuthError::InvalidToken);
        }
        ConsumeRefreshSessionResult::NotFound if refresh_claims.organization_id.is_some() => {
            return Err(AuthError::InvalidToken);
        }
        ConsumeRefreshSessionResult::NotFound => {}
    }

    // Compatibility path for refresh tokens issued before refresh_sessions existed.
    let client_id = match crate::db::consume_refresh_token(db, &payload.refresh_token).await {
        Ok(Some((_id, client_id))) => client_id,
        _ => return Err(AuthError::InvalidToken),
    };

    let principal = crate::db::ensure_client_principal(db, &client_id)
        .await
        .map_err(|_| AuthError::DatabaseError("Failed to resolve principal".to_string()))?
        .ok_or(AuthError::InvalidToken)?;
    let access_claims =
        access_claims_for_principal(&state, db, &principal, now, access_jti).await?;
    let access_token = state.jwt_keys.sign_token(&access_claims)?;

    let migrated_refresh_claims = Claims {
        sub: format!("client:{}", client_id),
        uid: None,
        principal_id: Some(principal.id.clone()),
        principal_type: Some("client".to_string()),
        organization_id: None,
        customer_support_grant_id: None,
        iss: state.config.jwt_issuer.clone(),
        aud: "admin-backend".to_string(),
        scope: vec!["refresh".into()],
        // Refresh tokens are not authorization artifacts and never carry roles.
        role: Vec::new(),
        iat: now,
        exp: now + state.config.refresh_token_expiry_seconds,
        jti: refresh_jti,
        token_type: "refresh".to_string(),
    };
    let migrated_refresh_token = state.jwt_keys.sign_token(&migrated_refresh_claims)?;
    let session_id = utils::generate_jti();
    crate::db::create_refresh_session(
        db,
        crate::db::CreateRefreshSessionParams {
            session_id: &session_id,
            principal_id: &principal.id,
            client_id: &client_id,
            organization_id: None,
            refresh_token_id: &migrated_refresh_claims.jti,
            refresh_token: &migrated_refresh_token,
            access_jti: &access_claims.jti,
            login_ip: None,
            user_agent: None,
            expires_at: migrated_refresh_claims.exp,
        },
    )
    .await
    .map_err(|_| AuthError::DatabaseError("Failed to create refresh session".to_string()))?;

    audit_event(
        &state,
        "auth.refresh.migrated",
        Some(&principal.subject),
        Some(&format!("session_id={}", session_id)),
    )
    .await;

    Ok(Json(AuthBody::new(
        access_token,
        Some(migrated_refresh_token),
        state.config.token_expiry_seconds,
    )))
}

pub async fn auth_logout_refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let refresh_claims = state.jwt_keys.decode_token(&payload.refresh_token);
    let refresh_claims = match refresh_claims {
        Ok(ref claims) if claims.token_type != "refresh" => {
            return Err(AuthError::TokenTypeInvalid)
        }
        Err(_) => return Err(AuthError::InvalidToken),
        Ok(claims) => claims,
    };

    let db = require_db(&state)?;
    let revoked_session =
        crate::db::revoke_refresh_session_by_token(db, &payload.refresh_token, Some("user_logout"))
            .await
            .map_err(|_| {
                AuthError::DatabaseError("Failed to revoke refresh session".to_string())
            })?;

    if revoked_session.is_none() {
        let _ = crate::db::revoke_refresh_token_by_token(db, &payload.refresh_token)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to revoke refresh token".to_string()))?;
    }

    audit_event(
        &state,
        "auth.refresh_session.logout",
        Some(refresh_claims.sub.as_str()),
        revoked_session
            .as_ref()
            .map(|session_id| format!("session_id={}", session_id))
            .as_deref(),
    )
    .await;

    Ok(Json(json!({
        "success": true,
        "message": "Refresh token session revoked"
    })))
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

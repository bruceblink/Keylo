use crate::db::{
    consume_email_verification_token, issue_email_verification_token,
    revoke_email_verification_token, ConsumeEmailVerificationTokenResult,
};
use crate::handlers::{extract_client_ip, PeerAddr};
use crate::mail::{MailDeliveryError, MailMessage};
use crate::models::{Claims, EmailVerificationConfirmRequest, User};
use crate::state::AppState;
use crate::utils::{require_db, ApiResponse};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

const EMAIL_VERIFICATION_SUBJECT: &str = "Verify your Keylo email address";

/// Build a same-origin verification URL without putting the one-time proof in
/// a request-visible query string; the frontend removes the fragment on load.
fn email_verification_link(state: &AppState, token: &str) -> String {
    format!(
        "{}/account/email-verification#token={}",
        state.config.oidc_issuer(),
        urlencoding::encode(token)
    )
}

fn error_response(
    status: StatusCode,
    error: &'static str,
    message: &'static str,
) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({
            "success": false,
            "error": error,
            "message": message,
        })),
    )
}

async fn audit_event(state: &AppState, event_type: &str, actor: Option<&str>, detail: &str) {
    if let Some(db) = &state.db {
        if let Err(error) = crate::db::create_audit_log(db, event_type, actor, Some(detail)).await {
            tracing::warn!(event_type, %error, "Failed to write email verification audit log");
        }
    }
}

async fn current_user(
    db: &sqlx::PgPool,
    claims: &Claims,
) -> Result<Option<User>, (StatusCode, Json<Value>)> {
    if matches!(claims.principal_type.as_deref(), Some(kind) if kind != "user") {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Unauthorized",
        ));
    }

    let result = if let Some(user_id) = claims.uid.as_deref() {
        crate::db::get_user_by_id(db, user_id).await
    } else if let Some(username) = claims.sub.strip_prefix("user:") {
        crate::db::get_user_by_username(db, username).await
    } else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Unauthorized",
        ));
    };

    result.map_err(|error| {
        tracing::warn!(%error, "Failed to resolve email verification user");
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database error",
        )
    })
}

fn mail_delivery_response(error: MailDeliveryError) -> (StatusCode, Json<Value>) {
    match error {
        MailDeliveryError::InvalidMessage => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "email_delivery_failed",
            "Email verification could not be sent",
        ),
        MailDeliveryError::NotConfigured
        | MailDeliveryError::Timeout
        | MailDeliveryError::TemporarilyUnavailable
        | MailDeliveryError::Rejected => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "email_delivery_unavailable",
            "Email verification service is unavailable",
        ),
    }
}

/// Issue a short-lived verification token for the authenticated user's current email.
///
/// Rate limiting is charged against both the user and the client IP before any
/// token is created. Delivery is attempted only after the database transaction
/// has committed; if the provider fails, the just-issued row is revoked so a
/// message that was not delivered can never become usable later.
pub async fn request_email_verification(
    State(state): State<AppState>,
    claims: Claims,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
) -> ApiResponse {
    let db = require_db(&state)?;
    let user = current_user(db, &claims)
        .await?
        .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "unauthorized", "Unauthorized"))?;
    if !user.active {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Unauthorized",
        ));
    }

    let client_ip = extract_client_ip(&headers, peer_addr, state.config.trust_proxy_headers);
    let user_rate_key = format!("email-verification:user:{}", user.id);
    let ip_rate_key = format!("email-verification:ip:{client_ip}");
    if !state
        .allow_auth_request_pair(
            &user_rate_key,
            state.config.auth_rate_limit_max_requests,
            &ip_rate_key,
            state.config.auth_global_rate_limit_max_requests,
            state.config.auth_rate_limit_window_seconds,
        )
        .await
    {
        state.runtime_metrics.rate_limit_rejection_observed();
        audit_event(
            &state,
            "user.email_verification.rate_limited",
            Some(&user.id),
            "Email verification request rate limit exceeded",
        )
        .await;
        return Err(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            "Too many requests",
        ));
    }

    if user.email_verified {
        return Ok(Json(json!({
            "success": true,
            "data": {
                "status": "already_verified",
                "email_verified": true,
            },
        })));
    }

    let issued = issue_email_verification_token(db, &user.id, state.config.token_expiry_seconds)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "Failed to issue email verification token");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database error",
            )
        })?;
    let Some(issued) = issued else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Unauthorized",
        ));
    };

    let message = MailMessage::new(
        issued.email.clone(),
        EMAIL_VERIFICATION_SUBJECT,
        format!(
            "Open this one-time Keylo email verification link to verify your email address:\n{}\n\nThe link expires soon and can only be used once.",
            email_verification_link(&state, &issued.token)
        ),
    );
    if let Err(error) = state.deliver_mail(message).await {
        let error_code = error.code();
        if let Err(revoke_error) = revoke_email_verification_token(db, &issued.id).await {
            tracing::warn!(%revoke_error, "Failed to revoke undelivered email verification token");
        }
        audit_event(
            &state,
            "user.email_verification.delivery_failed",
            Some(&user.id),
            &format!("reason={error_code}"),
        )
        .await;
        return Err(mail_delivery_response(error));
    }

    audit_event(
        &state,
        "user.email_verification.requested",
        Some(&user.id),
        &format!("expires_at={}", issued.expires_at),
    )
    .await;

    Ok(Json(json!({
        "success": true,
        "data": {
            "status": "sent",
            "email_verified": false,
        },
    })))
}

/// Consume a verification token once and mark the matching current email verified.
///
/// This endpoint intentionally accepts no user identifier: the token digest is
/// the sole lookup key, and every invalid condition maps to the same public
/// response. This keeps unknown, expired, replayed, revoked, and email-mismatch
/// tokens from becoming an account or state-enumeration oracle.
pub async fn confirm_email_verification(
    State(state): State<AppState>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Json(request): Json<EmailVerificationConfirmRequest>,
) -> ApiResponse {
    let db = require_db(&state)?;
    let client_ip = extract_client_ip(&headers, peer_addr, state.config.trust_proxy_headers);
    let rate_key = format!("email-verification:confirm:{client_ip}");
    if !state
        .allow_auth_request(
            &rate_key,
            state.config.auth_rate_limit_window_seconds,
            state.config.auth_global_rate_limit_max_requests,
        )
        .await
    {
        state.runtime_metrics.rate_limit_rejection_observed();
        audit_event(
            &state,
            "user.email_verification.confirm_rate_limited",
            None,
            "Email verification confirmation rate limit exceeded",
        )
        .await;
        return Err(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            "Too many requests",
        ));
    }

    let token = request.token.trim();
    if token.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_email_verification_token",
            "Invalid or expired email verification token",
        ));
    }

    match consume_email_verification_token(db, token)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "Failed to consume email verification token");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database error",
            )
        })? {
        ConsumeEmailVerificationTokenResult::Verified { .. } => Ok(Json(json!({
            "success": true,
            "data": {
                "email_verified": true,
            },
        }))),
        ConsumeEmailVerificationTokenResult::Invalid => Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_email_verification_token",
            "Invalid or expired email verification token",
        )),
    }
}

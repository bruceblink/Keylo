use crate::db::{
    consume_password_reset_token, issue_password_reset_token, revoke_password_reset_token,
    ConsumePasswordResetTokenResult,
};
use crate::handlers::{extract_client_ip, PeerAddr};
use crate::mail::MailMessage;
use crate::models::{PasswordResetConfirmRequest, PasswordResetRequest};
use crate::state::AppState;
use crate::utils::{require_db, validate_password_complexity, ApiResponse};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const PASSWORD_RESET_SUBJECT: &str = "Reset your Keylo password";
const PASSWORD_RESET_ACCEPTED_MESSAGE: &str =
    "If the account can be recovered, a password reset message will be sent";

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

async fn audit_event(state: &AppState, event_type: &str, detail: &str) {
    if let Some(db) = &state.db {
        if let Err(error) = crate::db::create_audit_log(db, event_type, None, Some(detail)).await {
            tracing::warn!(event_type, %error, "Failed to write password reset audit log");
        }
    }
}

fn identifier_rate_key(identifier: &str) -> String {
    format!(
        "password-reset:identifier:{}",
        hex::encode(Sha256::digest(identifier.as_bytes()))
    )
}

fn accepted_response() -> Json<Value> {
    Json(json!({
        "success": true,
        "data": {
            "status": "accepted",
            "message": PASSWORD_RESET_ACCEPTED_MESSAGE,
        },
    }))
}

/// Accept a recovery request without revealing whether the identifier exists.
///
/// The identifier bucket is hashed before entering the process-local or Redis
/// rate limiter. Eligible accounts receive a short-lived one-time message;
/// unknown, inactive, unverified, external-only, and delivery-failed cases all
/// return the same public result. A delivery failure revokes its newly-created
/// proof and is written to audit without exposing recipient or token values.
pub async fn request_password_reset(
    State(state): State<AppState>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Json(request): Json<PasswordResetRequest>,
) -> ApiResponse {
    let db = require_db(&state)?;
    let identifier = request.identifier.trim();
    let client_ip = extract_client_ip(&headers, peer_addr, state.config.trust_proxy_headers);
    let identifier_key = identifier_rate_key(identifier);
    let ip_rate_key = format!("password-reset:ip:{client_ip}");
    if !state
        .allow_auth_request_pair(
            &identifier_key,
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
            "user.password_reset.rate_limited",
            "Password reset request rate limit exceeded",
        )
        .await;
        return Err(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            "Too many requests",
        ));
    }

    if identifier.is_empty() {
        return Ok(accepted_response());
    }

    let issued = issue_password_reset_token(db, identifier, state.config.token_expiry_seconds)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "Failed to issue password reset token");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database error",
            )
        })?;
    let Some(issued) = issued else {
        return Ok(accepted_response());
    };

    let message = MailMessage::new(
        issued.email,
        PASSWORD_RESET_SUBJECT,
        format!(
            "Use this one-time Keylo password reset token: {}",
            issued.token
        ),
    );
    if let Err(error) = state.mail_provider.send(message).await {
        let error_code = error.code();
        if let Err(revoke_error) = revoke_password_reset_token(db, &issued.id).await {
            tracing::warn!(%revoke_error, "Failed to revoke undelivered password reset token");
        }
        audit_event(
            &state,
            "user.password_reset.delivery_failed",
            &format!("reason={error_code}"),
        )
        .await;
        return Ok(accepted_response());
    }

    audit_event(
        &state,
        "user.password_reset.requested",
        &format!("expires_at={}", issued.expires_at),
    )
    .await;
    Ok(accepted_response())
}

/// Replace a local password using one atomically consumed recovery proof.
///
/// Password complexity is checked before persistence. The database operation
/// then locks the token and account, changes the password, marks the account as
/// requiring a first-login password change, revokes old long-lived sessions,
/// and records a redacted audit event in one transaction. Invalid or replayed
/// proofs share one public error response.
pub async fn confirm_password_reset(
    State(state): State<AppState>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    Json(request): Json<PasswordResetConfirmRequest>,
) -> ApiResponse {
    let db = require_db(&state)?;
    let client_ip = extract_client_ip(&headers, peer_addr, state.config.trust_proxy_headers);
    let rate_key = format!("password-reset:confirm:{client_ip}");
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
            "user.password_reset.confirm_rate_limited",
            "Password reset confirmation rate limit exceeded",
        )
        .await;
        return Err(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            "Too many requests",
        ));
    }

    if request.token.trim().is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_password_reset_token",
            "Invalid or expired password reset token",
        ));
    }
    if let Err(message) = validate_password_complexity(&request.new_password) {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_password",
            message,
        ));
    }

    match consume_password_reset_token(db, request.token.trim(), &request.new_password)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "Failed to consume password reset token");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database error",
            )
        })? {
        ConsumePasswordResetTokenResult::Reset { .. } => Ok(Json(json!({
            "success": true,
            "data": {
                "password_reset": true,
                "password_change_required": true,
            },
        }))),
        ConsumePasswordResetTokenResult::Invalid => Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_password_reset_token",
            "Invalid or expired password reset token",
        )),
    }
}

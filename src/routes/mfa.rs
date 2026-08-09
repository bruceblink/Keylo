use axum::{extract::State, http::StatusCode, response::Json, routing::post, Router};
use chrono::Utc;
use serde_json::json;

use crate::{
    db::{
        consume_recovery_code_and_record_recent_verification,
        consume_totp_step_and_record_recent_verification, create_audit_log, delete_totp_credential,
        enable_totp_credential_with_recovery_codes, get_totp_credential,
        has_recent_mfa_verification, save_pending_totp_credential,
    },
    models::{
        decrypt_totp_seed, encrypt_totp_seed, generate_recovery_codes, generate_totp_seed,
        totp_provisioning_uri, verify_totp_code, Claims, MfaVerificationRequest,
        MfaVerificationResponse, TotpEnrollmentResponse, TotpVerificationResponse,
        VerifyTotpEnrollmentRequest, MFA_RECENT_VERIFICATION_SECONDS,
    },
    state::AppState,
    utils::{require_db, ApiResponse},
};

/// Routes that let an authenticated user enroll their own TOTP authenticator.
pub fn mfa_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/user/mfa/totp/enroll", post(start_totp_enrollment))
        .route("/v1/user/mfa/totp/verify", post(verify_totp_enrollment))
        .route("/v1/user/mfa/totp/reset", post(reset_totp_enrollment))
        .route("/v1/user/mfa/verify", post(verify_recent_mfa))
}

/// Require a fresh, token-bound MFA proof when this user has enabled TOTP.
pub async fn require_recent_mfa_for_enabled_user(
    state: &AppState,
    user_id: &str,
    token_jti: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let db = require_db(state)?;
    let credential = match get_totp_credential(db, user_id).await {
        Ok(credential) => credential,
        Err(error) => return Err(internal_error_response("Failed to load MFA state", &error)),
    };
    if credential.is_none_or(|credential| credential.enabled_at.is_none()) {
        return Ok(());
    }
    match has_recent_mfa_verification(db, user_id, token_jti).await {
        Ok(true) => Ok(()),
        Ok(false) => Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "success": false,
                "error": "Recent MFA verification is required",
                "mfa_required": true,
            })),
        )),
        Err(error) => Err(internal_error_response(
            "Failed to validate recent MFA verification",
            &error,
        )),
    }
}

/// Require recent MFA for a human caller while keeping machine client credentials usable for automation.
pub async fn require_recent_mfa_for_user_claims(
    state: &AppState,
    claims: &Claims,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if !mfa_required_for_claims(claims) {
        return Ok(());
    }
    let user_id = claims.uid.as_deref().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "error": "User principal is missing uid",
            })),
        )
    })?;
    require_recent_mfa_for_enabled_user(state, user_id, &claims.jti).await
}

/// Classify human user tokens, including legacy user tokens that carry a uid but no principal type.
fn mfa_required_for_claims(claims: &Claims) -> bool {
    matches!(claims.principal_type.as_deref(), Some("user")) || claims.uid.is_some()
}

/// Verify an enabled factor and bind the resulting short-lived proof to this access token.
async fn verify_recent_mfa(
    claims: Claims,
    State(state): State<AppState>,
    Json(request): Json<MfaVerificationRequest>,
) -> ApiResponse {
    let db = require_db(&state)?;
    let user_id = require_user_id(&claims)?;
    let has_totp = request.totp_code.is_some();
    let has_recovery = request.recovery_code.is_some();
    if has_totp == has_recovery {
        return Err(bad_request_response("Provide exactly one MFA factor"));
    }
    let credential = match get_totp_credential(db, &user_id).await {
        Ok(Some(credential)) if credential.enabled_at.is_some() => credential,
        Ok(_) => return Err(bad_request_response("TOTP is not enabled")),
        Err(error) => return Err(internal_error_response("Failed to load MFA state", &error)),
    };
    let now = Utc::now().timestamp();
    let verified_until = now + MFA_RECENT_VERIFICATION_SECONDS;
    let (method, accepted) = if let Some(code) = request.totp_code {
        let key = match state.config.mfa_secret_key_bytes() {
            Ok(key) => key,
            Err(_) => return Err(mfa_unavailable_response()),
        };
        let seed = match decrypt_totp_seed(&credential.encrypted_seed, &key) {
            Ok(seed) => seed,
            Err(_) => return Err(mfa_unavailable_response()),
        };
        let step = match u64::try_from(now)
            .ok()
            .and_then(|timestamp| verify_totp_code(&seed, &code, timestamp).ok().flatten())
        {
            Some(step) => step,
            None => return Err(bad_request_response("Invalid MFA code")),
        };
        (
            "totp",
            consume_totp_step_and_record_recent_verification(
                db,
                &user_id,
                step,
                &claims.jti,
                verified_until,
            )
            .await,
        )
    } else {
        (
            "recovery_code",
            consume_recovery_code_and_record_recent_verification(
                db,
                &user_id,
                request.recovery_code.as_deref().unwrap_or_default(),
                &claims.jti,
                verified_until,
            )
            .await,
        )
    };
    match accepted {
        Ok(true) => {}
        Ok(false) => return Err(bad_request_response("Invalid or already used MFA code")),
        Err(error) => return Err(internal_error_response("Failed to verify MFA", &error)),
    }
    if let Err(error) = create_audit_log(
        db,
        "mfa.verified",
        Some(&claims.sub),
        Some(&format!("user_id={user_id}, method={method}")),
    )
    .await
    {
        tracing::warn!(error = %error, "Failed to write MFA verification audit log");
    }

    Ok(Json(json!({
        "success": true,
        "data": MfaVerificationResponse { method: method.to_string(), verified_until }
    })))
}

/// Reset enabled TOTP only after a proof from the same access token was recently verified.
async fn reset_totp_enrollment(claims: Claims, State(state): State<AppState>) -> ApiResponse {
    let db = require_db(&state)?;
    let user_id = require_user_id(&claims)?;
    require_recent_mfa_for_enabled_user(&state, &user_id, &claims.jti).await?;
    match delete_totp_credential(db, &user_id).await {
        Ok(true) => {}
        Ok(false) => return Err(not_found_response("TOTP is not enabled")),
        Err(error) => return Err(internal_error_response("Failed to reset TOTP", &error)),
    }
    if let Err(error) = create_audit_log(
        db,
        "mfa.totp.reset",
        Some(&claims.sub),
        Some(&format!("user_id={user_id}")),
    )
    .await
    {
        tracing::warn!(error = %error, "Failed to write TOTP reset audit log");
    }

    Ok(Json(
        json!({ "success": true, "data": { "enabled": false } }),
    ))
}

/// Start a replacement-safe TOTP enrollment and return the secret only to its owner.
async fn start_totp_enrollment(claims: Claims, State(state): State<AppState>) -> ApiResponse {
    let db = require_db(&state)?;
    let user_id = require_user_id(&claims)?;
    let key = match state.config.mfa_secret_key_bytes() {
        Ok(key) => key,
        Err(_) => return Err(mfa_unavailable_response()),
    };

    let user = match crate::db::user::get_user_by_id(db, &user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return Err(not_found_response("User not found")),
        Err(error) => return Err(internal_error_response("Failed to load user", &error)),
    };
    match get_totp_credential(db, &user_id).await {
        Ok(Some(credential)) if credential.enabled_at.is_some() => {
            return Err(conflict_response("TOTP is already enabled"));
        }
        Ok(_) => {}
        Err(error) => return Err(internal_error_response("Failed to load MFA state", &error)),
    }

    let seed = generate_totp_seed();
    let encrypted_seed = match encrypt_totp_seed(&seed, &key) {
        Ok(encrypted_seed) => encrypted_seed,
        Err(_) => return Err(mfa_unavailable_response()),
    };
    let provisioning_uri = match totp_provisioning_uri(&seed, "Keylo", &user.email) {
        Ok(uri) => uri,
        Err(_) => return Err(bad_request_response("Unable to create TOTP enrollment")),
    };
    if let Err(error) = save_pending_totp_credential(db, &user_id, &encrypted_seed).await {
        return Err(internal_error_response(
            "Failed to save MFA enrollment",
            &error,
        ));
    }
    if let Err(error) = create_audit_log(
        db,
        "mfa.totp.enrollment_started",
        Some(&claims.sub),
        Some(&format!("user_id={user_id}")),
    )
    .await
    {
        tracing::warn!(error = %error, "Failed to write TOTP enrollment audit log");
    }

    Ok(Json(json!({
        "success": true,
        "data": TotpEnrollmentResponse {
            manual_entry_key: seed,
            provisioning_uri,
        }
    })))
}

/// Verify the pending seed once before enabling it and recording a security audit event.
async fn verify_totp_enrollment(
    claims: Claims,
    State(state): State<AppState>,
    Json(request): Json<VerifyTotpEnrollmentRequest>,
) -> ApiResponse {
    let db = require_db(&state)?;
    let user_id = require_user_id(&claims)?;
    let key = match state.config.mfa_secret_key_bytes() {
        Ok(key) => key,
        Err(_) => return Err(mfa_unavailable_response()),
    };

    let credential = match get_totp_credential(db, &user_id).await {
        Ok(Some(credential)) if credential.enabled_at.is_none() => credential,
        Ok(Some(_)) => return Err(conflict_response("TOTP is already enabled")),
        Ok(None) => return Err(not_found_response("No pending TOTP enrollment")),
        Err(error) => return Err(internal_error_response("Failed to load MFA state", &error)),
    };
    let seed = match decrypt_totp_seed(&credential.encrypted_seed, &key) {
        Ok(seed) => seed,
        Err(_) => return Err(mfa_unavailable_response()),
    };
    let now = Utc::now().timestamp();
    let step = match u64::try_from(now).ok().and_then(|timestamp| {
        verify_totp_code(&seed, &request.code, timestamp)
            .ok()
            .flatten()
    }) {
        Some(step) => step,
        None => return Err(bad_request_response("Invalid TOTP code")),
    };
    let recovery_codes = generate_recovery_codes();
    match enable_totp_credential_with_recovery_codes(db, &user_id, step, &recovery_codes).await {
        Ok(true) => {}
        Ok(false) => return Err(conflict_response("TOTP enrollment is no longer pending")),
        Err(error) => return Err(internal_error_response("Failed to enable TOTP", &error)),
    }
    if let Err(error) = create_audit_log(
        db,
        "mfa.totp.enabled",
        Some(&claims.sub),
        Some(&format!("user_id={user_id}")),
    )
    .await
    {
        tracing::warn!(error = %error, "Failed to write TOTP enabled audit log");
    }

    Ok(Json(json!({
        "success": true,
        "data": TotpVerificationResponse { enabled: true, recovery_codes }
    })))
}

/// Accept only user principals with a stable user identifier for self-service MFA changes.
fn require_user_id(claims: &Claims) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    if matches!(claims.principal_type.as_deref(), Some(kind) if kind != "user") {
        return Err(unauthorized_response());
    }
    claims.uid.clone().ok_or_else(unauthorized_response)
}

fn unauthorized_response() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "success": false, "error": "A user access token is required" })),
    )
}

fn mfa_unavailable_response() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "success": false, "error": "MFA is not configured" })),
    )
}

fn bad_request_response(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "success": false, "error": message })),
    )
}

fn conflict_response(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::CONFLICT,
        Json(json!({ "success": false, "error": message })),
    )
}

fn not_found_response(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "success": false, "error": message })),
    )
}

fn internal_error_response(
    message: &str,
    error: &dyn std::fmt::Display,
) -> (StatusCode, Json<serde_json::Value>) {
    tracing::error!(error = %error, "{message}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "success": false, "error": message })),
    )
}

#[cfg(test)]
mod tests {
    use super::{mfa_required_for_claims, require_user_id};
    use crate::models::Claims;

    fn claims(uid: Option<&str>, principal_type: Option<&str>) -> Claims {
        Claims {
            sub: "user:alice".to_string(),
            uid: uid.map(str::to_string),
            principal_id: Some("principal-1".to_string()),
            principal_type: principal_type.map(str::to_string),
            organization_id: None,
            iss: "keylo".to_string(),
            aud: "admin-backend".to_string(),
            scope: vec![],
            role: vec![],
            token_type: "access".to_string(),
            exp: 1,
            iat: 1,
            jti: "jti-1".to_string(),
        }
    }

    #[test]
    fn mfa_requires_a_user_principal_with_uid() {
        assert_eq!(
            require_user_id(&claims(Some("user-1"), Some("user"))).unwrap(),
            "user-1"
        );
        assert!(require_user_id(&claims(None, Some("user"))).is_err());
        assert!(require_user_id(&claims(Some("user-1"), Some("client"))).is_err());
    }

    #[test]
    fn sensitive_actions_require_mfa_for_user_claims_only() {
        let user = Claims {
            sub: "user:alice".to_string(),
            uid: Some("user-1".to_string()),
            principal_id: Some("principal-1".to_string()),
            principal_type: Some("user".to_string()),
            organization_id: None,
            iss: "keylo".to_string(),
            aud: "keylo".to_string(),
            exp: 0,
            iat: 0,
            jti: "token-1".to_string(),
            role: vec![],
            scope: vec![],
            token_type: "access".to_string(),
        };
        let client = Claims {
            sub: "client:automation".to_string(),
            uid: None,
            principal_id: Some("principal-2".to_string()),
            principal_type: Some("client".to_string()),
            ..user.clone()
        };
        assert!(mfa_required_for_claims(&user));
        assert!(!mfa_required_for_claims(&client));
    }
}

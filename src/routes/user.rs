use crate::utils::validate_password_complexity;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde_json::json;
use std::collections::HashMap;

use crate::{
    db::*,
    errors::is_unique_violation,
    handlers::user::{
        get_third_party_import_job_status, import_third_party_users, start_third_party_import_job,
    },
    models::{Claims, *},
    state::AppState,
    utils::{require_db, ApiResponse},
};

enum SelfUserIdentity<'a> {
    Id(&'a str),
    Username(&'a str),
}

fn self_user_identity_from_claims(claims: &Claims) -> Result<SelfUserIdentity<'_>, &'static str> {
    if matches!(claims.principal_type.as_deref(), Some(kind) if kind != "user") {
        return Err("Missing uid in token");
    }

    if let Some(uid) = claims.uid.as_deref() {
        return Ok(SelfUserIdentity::Id(uid));
    }

    claims
        .sub
        .strip_prefix("user:")
        .map(SelfUserIdentity::Username)
        .ok_or("Missing uid in token")
}

fn validate_optional_password(password: Option<&str>) -> Result<(), &'static str> {
    if let Some(password) = password {
        validate_password_complexity(password)?;
    }

    Ok(())
}

fn invalid_password_response(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "success": false,
            "error": message,
        })),
    )
}

pub fn user_routes() -> Router<AppState> {
    admin_user_routes().merge(self_user_routes())
}

pub fn admin_user_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/admin/users", get(list_users_handler))
        .route("/v1/admin/users", post(create_user_handler))
        .route("/v1/admin/users/provision", post(provision_user_handler))
        .route("/v1/admin/users/{user_id}", get(get_user_handler))
        .route("/v1/admin/users/{user_id}", put(update_user_handler))
        .route("/v1/admin/users/{user_id}", delete(delete_user_handler))
        .route(
            "/v1/admin/users/{user_id}/effective-permissions",
            get(get_user_effective_permissions_handler),
        )
        .route(
            "/v1/admin/users/migrations/import",
            post(import_third_party_users),
        )
        .route(
            "/v1/admin/users/migrations/jobs",
            post(start_third_party_import_job),
        )
        .route(
            "/v1/admin/users/migrations/jobs/{job_id}",
            get(get_third_party_import_job_status),
        )
        .route(
            "/v1/admin/users/{user_id}/reset-password",
            post(reset_user_password_handler),
        )
}

pub fn self_user_routes() -> Router<AppState> {
    Router::new().route("/v1/user/change-password", post(change_password_handler))
}

async fn list_users_handler(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResponse {
    let db = require_db(&state)?;
    let limit = params
        .get("limit")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 500);
    let offset = params
        .get("offset")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0)
        .max(0);

    match list_users(db, limit, offset).await {
        Ok(users) => Ok(Json(json!({
            "success": true,
            "data": users,
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to list users: {}", e),
            })),
        )),
    }
}

async fn create_user_handler(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> ApiResponse {
    let db = require_db(&state)?;

    if let Err(msg) = validate_optional_password(req.password.as_deref()) {
        return Err(invalid_password_response(msg));
    }

    match create_user(db, &req.username, &req.email, req.password.as_deref()).await {
        Ok(user) => Ok(Json(json!({
            "success": true,
            "data": user,
        }))),
        Err(e) => {
            if is_unique_violation(e.as_ref()) {
                Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "success": false,
                        "error": "Username or email already exists",
                    })),
                ))
            } else {
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "success": false,
                        "error": format!("Failed to create user: {}", e),
                    })),
                ))
            }
        }
    }
}

async fn provision_user_handler(
    claims: Claims,
    State(state): State<AppState>,
    Json(req): Json<ProvisionUserRequest>,
) -> ApiResponse {
    let db = require_db(&state)?;

    if let Err(msg) = validate_optional_password(req.password.as_deref()) {
        return Err(invalid_password_response(msg));
    }

    match provision_user_with_roles(
        db,
        &req.username,
        &req.email,
        req.password.as_deref(),
        &req.role_ids,
        &req.role_names,
    )
    .await
    {
        Ok((user, roles, permissions)) => {
            create_audit_log(
                db,
                "user.provisioned",
                Some(&claims.sub),
                Some(&format!(
                    "user_id={}, role_ids={}, role_names={}",
                    user.id,
                    req.role_ids.join(","),
                    req.role_names.join(",")
                )),
            )
            .await
            .ok();

            Ok(Json(json!({
                "success": true,
                "data": ProvisionUserResponse {
                    user,
                    roles,
                    permissions,
                }
            })))
        }
        Err(e) => {
            let message = e.to_string();
            if is_unique_violation(e.as_ref()) {
                Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "success": false,
                        "error": "conflict",
                        "message": "Username or email already exists",
                    })),
                ))
            } else if message.contains("role_not_bound") {
                Err((
                    StatusCode::NOT_FOUND,
                    Json(json!({
                        "success": false,
                        "error": "role_not_bound",
                        "message": message,
                    })),
                ))
            } else if message.starts_with("role_not_assignable_to_principal_type")
                || message.starts_with("invalid_role_assignable_to")
            {
                Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "success": false,
                        "error": "invalid_role_assignment",
                        "message": message,
                    })),
                ))
            } else {
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "success": false,
                        "error": "internal_server_error",
                        "message": format!("Failed to provision user: {}", message),
                    })),
                ))
            }
        }
    }
}

async fn get_user_effective_permissions_handler(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> ApiResponse {
    let db = require_db(&state)?;

    match get_effective_permissions(db, &user_id).await {
        Ok((roles, permissions)) => Ok(Json(json!({
            "success": true,
            "data": EffectivePermissionsResponse {
                user_id,
                roles,
                permissions,
            }
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to get effective permissions: {}", e),
            })),
        )),
    }
}

async fn get_user_handler(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> ApiResponse {
    let db = require_db(&state)?;

    match crate::db::user::get_user_by_id(db, &user_id).await {
        Ok(Some(user)) => Ok(Json(json!({
            "success": true,
            "data": user,
        }))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "User not found",
            })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to fetch user: {}", e),
            })),
        )),
    }
}

async fn update_user_handler(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> ApiResponse {
    let db = require_db(&state)?;

    if let Err(msg) = validate_optional_password(req.password.as_deref()) {
        return Err(invalid_password_response(msg));
    }

    match crate::db::user::update_user(
        db,
        &user_id,
        req.username.as_deref(),
        req.email.as_deref(),
        req.password.as_deref(),
        req.active,
    )
    .await
    {
        Ok(Some(user)) => Ok(Json(json!({
            "success": true,
            "data": user,
        }))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "User not found",
            })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to update user: {}", e),
            })),
        )),
    }
}

async fn delete_user_handler(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> ApiResponse {
    let db = require_db(&state)?;

    match crate::db::user::delete_user(db, &user_id).await {
        Ok(true) => Ok(Json(json!({
            "success": true,
            "message": "User deleted successfully",
        }))),
        Ok(false) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "User not found",
            })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to delete user: {}", e),
            })),
        )),
    }
}

async fn reset_user_password_handler(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(req): Json<ResetPasswordRequest>,
) -> ApiResponse {
    let db = require_db(&state)?;

    if let Err(msg) = validate_optional_password(Some(&req.password)) {
        return Err(invalid_password_response(msg));
    }

    match crate::db::user::reset_user_password(db, &user_id, &req.password).await {
        Ok(true) => Ok(Json(json!({
            "success": true,
            "message": "Password reset successfully",
        }))),
        Ok(false) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "User not found",
            })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to reset password: {}", e),
            })),
        )),
    }
}

async fn change_password_handler(
    State(state): State<AppState>,
    claims: Claims,
    Json(req): Json<ChangePasswordRequest>,
) -> ApiResponse {
    let db = require_db(&state)?;

    let user_id = match self_user_identity_from_claims(&claims) {
        Ok(SelfUserIdentity::Id(uid)) => uid.to_string(),
        Ok(SelfUserIdentity::Username(username)) => {
            tracing::debug!("Looking up user by username: {}", username);
            match crate::db::user::get_user_by_username(db, username).await {
                Ok(Some(user)) => {
                    tracing::debug!("Found user: {}", user.id);
                    user.id
                }
                Ok(None) => {
                    tracing::warn!("User not found for username: {}", username);
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "success": false,
                            "error": "User not found",
                        })),
                    ));
                }
                Err(e) => {
                    tracing::warn!("Database error: {}", e);
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({
                            "success": false,
                            "error": format!("Failed to find user: {}", e),
                        })),
                    ));
                }
            }
        }
        Err(message) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "success": false,
                    "error": message,
                })),
            ));
        }
    };

    // 验证新密码复杂度
    if let Err(msg) = validate_password_complexity(&req.new_password) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": msg,
            })),
        ));
    }

    match crate::db::user::change_user_password(
        db,
        &user_id,
        &req.current_password,
        &req.new_password,
    )
    .await
    {
        Ok(true) => Ok(Json(json!({
            "success": true,
            "message": "Password changed successfully",
        }))),
        Ok(false) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "Current password is incorrect or user not found",
            })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to change password: {}", e),
            })),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(sub: &str, uid: Option<&str>, principal_type: Option<&str>) -> Claims {
        Claims {
            sub: sub.to_string(),
            uid: uid.map(str::to_string),
            principal_id: Some("principal-1".to_string()),
            principal_type: principal_type.map(str::to_string),
            iss: "keylo".to_string(),
            aud: "admin-backend".to_string(),
            scope: vec!["read".to_string(), "write".to_string()],
            role: vec!["user".to_string()],
            token_type: "access".to_string(),
            exp: 1,
            iat: 1,
            jti: "jti-1".to_string(),
        }
    }

    #[test]
    fn self_user_identity_uses_uid() {
        let claims = claims("user:alice", Some("user-id"), Some("user"));

        match self_user_identity_from_claims(&claims).unwrap() {
            SelfUserIdentity::Id(value) => assert_eq!(value, "user-id"),
            SelfUserIdentity::Username(_) => panic!("expected uid identity"),
        }
    }

    #[test]
    fn self_user_identity_allows_legacy_user_subject() {
        let claims = claims("user:alice", None, None);

        match self_user_identity_from_claims(&claims).unwrap() {
            SelfUserIdentity::Username(value) => assert_eq!(value, "alice"),
            SelfUserIdentity::Id(_) => panic!("expected username identity"),
        }
    }

    #[test]
    fn self_user_identity_rejects_client_principal() {
        let claims = claims("client:web", Some("user-id"), Some("client"));

        assert!(self_user_identity_from_claims(&claims).is_err());
    }

    #[test]
    fn validate_optional_password_allows_absent_password() {
        assert!(validate_optional_password(None).is_ok());
    }

    #[test]
    fn validate_optional_password_rejects_weak_password() {
        assert_eq!(
            validate_optional_password(Some("short")).unwrap_err(),
            "Password must be at least 8 characters long"
        );
    }

    #[test]
    fn validate_optional_password_accepts_complex_password() {
        assert!(validate_optional_password(Some("Password123!")).is_ok());
    }
}

use axum::response::{IntoResponse, Response};
use axum::Json;
use http::StatusCode;
use serde::Serialize;
use std::fmt;

pub fn is_unique_violation(err: &(dyn std::error::Error + 'static)) -> bool {
    err.downcast_ref::<sqlx::Error>()
        .and_then(|sqlx_err| match sqlx_err {
            sqlx::Error::Database(db_err) => Some(db_err.as_ref()),
            _ => None,
        })
        .is_some_and(|db_err| db_err.code().as_deref() == Some("23505"))
}

#[derive(Debug)]
pub enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
    ExpiredToken,
    DatabaseError(String),
    NotFound,
    Unauthorized,
    Forbidden,
    InsufficientScope,
    InsufficientAudience,
    InsufficientRole,
    InvalidAudience,
    TokenTypeInvalid,
    PermissionNotBound,
    RoleNotBound,
    ServiceClientNotAuthorized,
    TooManyRequests,
    Conflict(String),
    InvalidRequest(String),
    InternalServerError(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::WrongCredentials => write!(f, "Wrong credentials"),
            AuthError::MissingCredentials => write!(f, "Missing credentials"),
            AuthError::TokenCreation => write!(f, "Token creation error"),
            AuthError::InvalidToken => write!(f, "Invalid token"),
            AuthError::ExpiredToken => write!(f, "Token expired"),
            AuthError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            AuthError::NotFound => write!(f, "Resource not found"),
            AuthError::Unauthorized => write!(f, "Unauthorized"),
            AuthError::Forbidden => write!(f, "Forbidden"),
            AuthError::InsufficientScope => write!(f, "Insufficient scope"),
            AuthError::InsufficientAudience => write!(f, "Insufficient audience"),
            AuthError::InsufficientRole => write!(f, "Insufficient role"),
            AuthError::InvalidAudience => write!(f, "Invalid audience"),
            AuthError::TokenTypeInvalid => write!(f, "Token type invalid"),
            AuthError::PermissionNotBound => write!(f, "Permission not bound"),
            AuthError::RoleNotBound => write!(f, "Role not bound"),
            AuthError::ServiceClientNotAuthorized => {
                write!(f, "Service client not authorized")
            }
            AuthError::TooManyRequests => write!(f, "Too many requests"),
            AuthError::Conflict(msg) => write!(f, "Conflict: {}", msg),
            AuthError::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
            AuthError::InternalServerError(msg) => write!(f, "Internal server error: {}", msg),
        }
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    code: u16,
    error: &'static str,
    message: String,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, code, error, message) = match self {
            AuthError::WrongCredentials => (
                StatusCode::UNAUTHORIZED,
                1001,
                "wrong_credentials",
                "Wrong credentials".to_string(),
            ),
            AuthError::MissingCredentials => (
                StatusCode::BAD_REQUEST,
                1002,
                "missing_credentials",
                "Missing credentials".to_string(),
            ),
            AuthError::TokenCreation => (
                StatusCode::INTERNAL_SERVER_ERROR,
                1003,
                "token_creation_error",
                "Token creation error".to_string(),
            ),
            AuthError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                1004,
                "invalid_token",
                "Invalid token".to_string(),
            ),
            AuthError::ExpiredToken => (
                StatusCode::UNAUTHORIZED,
                1005,
                "expired_token",
                "Token expired".to_string(),
            ),
            AuthError::DatabaseError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                1006,
                "database_error",
                "Database error".to_string(),
            ),
            AuthError::NotFound => (
                StatusCode::NOT_FOUND,
                1007,
                "not_found",
                "Resource not found".to_string(),
            ),
            AuthError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                1008,
                "unauthorized",
                "Unauthorized".to_string(),
            ),
            AuthError::Forbidden => (
                StatusCode::FORBIDDEN,
                1009,
                "forbidden",
                "Forbidden".to_string(),
            ),
            AuthError::InsufficientScope => (
                StatusCode::FORBIDDEN,
                1012,
                "insufficient_scope",
                "Insufficient scope".to_string(),
            ),
            AuthError::InsufficientAudience => (
                StatusCode::FORBIDDEN,
                1013,
                "invalid_audience",
                "Invalid audience".to_string(),
            ),
            AuthError::InsufficientRole => (
                StatusCode::FORBIDDEN,
                1014,
                "insufficient_role",
                "Insufficient role".to_string(),
            ),
            AuthError::InvalidAudience => (
                StatusCode::UNAUTHORIZED,
                1016,
                "invalid_audience",
                "Invalid audience".to_string(),
            ),
            AuthError::TokenTypeInvalid => (
                StatusCode::FORBIDDEN,
                1017,
                "token_type_invalid",
                "Token type invalid".to_string(),
            ),
            AuthError::PermissionNotBound => (
                StatusCode::NOT_FOUND,
                1018,
                "permission_not_bound",
                "Permission not bound".to_string(),
            ),
            AuthError::RoleNotBound => (
                StatusCode::NOT_FOUND,
                1019,
                "role_not_bound",
                "Role not bound".to_string(),
            ),
            AuthError::ServiceClientNotAuthorized => (
                StatusCode::FORBIDDEN,
                1015,
                "service_client_not_authorized",
                "Service client not authorized".to_string(),
            ),
            AuthError::TooManyRequests => (
                StatusCode::TOO_MANY_REQUESTS,
                1011,
                "too_many_requests",
                "Too many requests".to_string(),
            ),
            AuthError::Conflict(message) => (StatusCode::CONFLICT, 1020, "conflict", message),
            AuthError::InvalidRequest(message) => {
                (StatusCode::BAD_REQUEST, 1021, "invalid_request", message)
            }
            AuthError::InternalServerError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                1010,
                "internal_server_error",
                "Internal server error".to_string(),
            ),
        };

        let body = Json(ErrorResponse {
            code,
            error,
            message,
        });
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn conflict_response_includes_specific_message() {
        let message = "Service client 'billing' already exists".to_string();
        let response = AuthError::Conflict(message.clone()).into_response();

        assert_eq!(response.status(), StatusCode::CONFLICT);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["error"], "conflict");
        assert_eq!(json["message"], message);
    }

    #[tokio::test]
    async fn invalid_audience_is_an_authentication_failure() {
        let response = AuthError::InvalidAudience.into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["error"], "invalid_audience");
    }
}

use axum::response::{IntoResponse, Response};
use axum::Json;
use http::StatusCode;
use serde::Serialize;
use std::fmt;

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
                "Wrong credentials",
            ),
            AuthError::MissingCredentials => (
                StatusCode::BAD_REQUEST,
                1002,
                "missing_credentials",
                "Missing credentials",
            ),
            AuthError::TokenCreation => (
                StatusCode::INTERNAL_SERVER_ERROR,
                1003,
                "token_creation_error",
                "Token creation error",
            ),
            AuthError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                1004,
                "invalid_token",
                "Invalid token",
            ),
            AuthError::ExpiredToken => (
                StatusCode::UNAUTHORIZED,
                1005,
                "expired_token",
                "Token expired",
            ),
            AuthError::DatabaseError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                1006,
                "database_error",
                "Database error",
            ),
            AuthError::NotFound => (
                StatusCode::NOT_FOUND,
                1007,
                "not_found",
                "Resource not found",
            ),
            AuthError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                1008,
                "unauthorized",
                "Unauthorized",
            ),
            AuthError::Forbidden => (StatusCode::FORBIDDEN, 1009, "forbidden", "Forbidden"),
            AuthError::InsufficientScope => (
                StatusCode::FORBIDDEN,
                1012,
                "insufficient_scope",
                "Insufficient scope",
            ),
            AuthError::InsufficientAudience => (
                StatusCode::FORBIDDEN,
                1013,
                "invalid_audience",
                "Invalid audience",
            ),
            AuthError::InsufficientRole => (
                StatusCode::FORBIDDEN,
                1014,
                "insufficient_role",
                "Insufficient role",
            ),
            AuthError::InvalidAudience => (
                StatusCode::FORBIDDEN,
                1016,
                "invalid_audience",
                "Invalid audience",
            ),
            AuthError::TokenTypeInvalid => (
                StatusCode::FORBIDDEN,
                1017,
                "token_type_invalid",
                "Token type invalid",
            ),
            AuthError::PermissionNotBound => (
                StatusCode::NOT_FOUND,
                1018,
                "permission_not_bound",
                "Permission not bound",
            ),
            AuthError::RoleNotBound => (
                StatusCode::NOT_FOUND,
                1019,
                "role_not_bound",
                "Role not bound",
            ),
            AuthError::ServiceClientNotAuthorized => (
                StatusCode::FORBIDDEN,
                1015,
                "service_client_not_authorized",
                "Service client not authorized",
            ),
            AuthError::TooManyRequests => (
                StatusCode::TOO_MANY_REQUESTS,
                1011,
                "too_many_requests",
                "Too many requests",
            ),
            AuthError::InternalServerError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                1010,
                "internal_server_error",
                "Internal server error",
            ),
        };

        let body = Json(ErrorResponse {
            code,
            error,
            message: message.to_string(),
        });
        (status, body).into_response()
    }
}

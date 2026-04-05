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
            AuthError::InternalServerError(msg) => write!(f, "Internal server error: {}", msg),
        }
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    code: u16,
    message: String,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, 1001, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, 1002, "Missing credentials"),
            AuthError::TokenCreation => (
                StatusCode::INTERNAL_SERVER_ERROR,
                1003,
                "Token creation error",
            ),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, 1004, "Invalid token"),
            AuthError::ExpiredToken => (StatusCode::UNAUTHORIZED, 1005, "Token expired"),
            AuthError::DatabaseError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, 1006, "Database error")
            }
            AuthError::NotFound => (StatusCode::NOT_FOUND, 1007, "Resource not found"),
            AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, 1008, "Unauthorized"),
            AuthError::Forbidden => (StatusCode::FORBIDDEN, 1009, "Forbidden"),
            AuthError::InternalServerError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                1010,
                "Internal server error",
            ),
        };

        let body = Json(ErrorResponse {
            code,
            message: message.to_string(),
        });
        (status, body).into_response()
    }
}

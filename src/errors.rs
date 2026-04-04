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
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, 1003, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, 1004, "Invalid token"),
            AuthError::DatabaseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, 1005, "Database error"),
            AuthError::NotFound => (StatusCode::NOT_FOUND, 1006, "Resource not found"),
            AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, 1007, "Unauthorized"),
            AuthError::Forbidden => (StatusCode::FORBIDDEN, 1008, "Forbidden"),
            AuthError::InternalServerError(_) => (StatusCode::INTERNAL_SERVER_ERROR, 1009, "Internal server error"),
        };

        let body = Json(ErrorResponse {
            code,
            message: message.to_string(),
        });
        (status, body).into_response()
    }
}
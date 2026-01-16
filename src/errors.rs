use axum::response::{IntoResponse, Response};
use axum::Json;
use http::StatusCode;
use serde::Serialize;

#[derive(Debug)]
pub enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
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
        };

        let body = Json(ErrorResponse {
            code,
            message: message.to_string(),
        });
        (status, body).into_response()
    }
}
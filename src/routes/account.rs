use crate::handlers::account::{email_verification_page, password_reset_page};
use crate::state::AppState;
use axum::routing::get;
use axum::Router;

/// Mount the anonymous password recovery page while leaving token handling in
/// the existing API endpoints.
pub fn account_routes() -> Router<AppState> {
    Router::new()
        .route("/account/password-reset", get(password_reset_page))
        .route("/account/email-verification", get(email_verification_page))
}

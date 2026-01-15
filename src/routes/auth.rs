use axum::Router;
use axum::routing::post;
use crate::handlers::{auth_logout, auth_me, auth_token};

pub fn router() -> Router {
    Router::new()
        .route("/v1/auth/token", post(auth_token))
        .route("/v1/auth/logout", post(auth_logout))
        .route("/v1/auth/me", axum::routing::get(auth_me))
}
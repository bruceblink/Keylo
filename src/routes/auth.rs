use crate::handlers::user::register_user;
use crate::handlers::{
    auth_blacklist_token, auth_get_blacklisted_tokens, auth_logout, auth_me, auth_refresh,
    auth_token,
};
use crate::state::AppState;
use axum::routing::{get, post};
use axum::Router;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/auth/logout", post(auth_logout))
        .route("/v1/auth/me", get(auth_me))
        .route("/v1/admin/blacklist", post(auth_blacklist_token))
        .route(
            "/v1/admin/blacklisted-tokens",
            get(auth_get_blacklisted_tokens),
        )
}

pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/v1/auth/register", post(register_user))
        .route("/v1/auth/token", post(auth_token))
        .route("/v1/auth/refresh", post(auth_refresh))
}

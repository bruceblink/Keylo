use crate::{handlers::oidc, state::AppState};
use axum::{
    routing::{get, post, put},
    Router,
};

pub fn admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/admin/oidc/clients",
            get(oidc::list_clients).post(oidc::create_client),
        )
        .route(
            "/v1/admin/oidc/clients/{client_id}",
            put(oidc::update_client),
        )
}

pub fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/oidc/authorize", get(oidc::authorize))
        .route("/v1/oidc/login", post(oidc::login))
        .route("/v1/oidc/token", post(oidc::token))
        .route("/v1/oidc/userinfo", get(oidc::userinfo))
        .route("/.well-known/openid-configuration", get(oidc::discovery))
}

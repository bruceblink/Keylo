use crate::{handlers::oidc, state::AppState};
use axum::{
    routing::{get, put},
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
    Router::new().route(
        "/.well-known/openid-configuration",
        get(oidc::unavailable_discovery),
    )
}

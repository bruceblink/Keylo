use crate::{handlers::oidc, state::AppState};
use axum::{
    routing::{get, post},
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
            get(oidc::get_client).put(oidc::update_client),
        )
        .route(
            "/v1/admin/oidc/clients/{client_id}/rotate-secret",
            post(oidc::rotate_client_secret),
        )
}

/// Tenant owners and administrators manage only clients persisted in their active organization.
pub fn organization_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/organizations/{organization_id}/oidc/clients",
            get(oidc::list_organization_clients).post(oidc::create_organization_client),
        )
        .route(
            "/v1/organizations/{organization_id}/oidc/clients/{client_id}",
            get(oidc::get_organization_client).put(oidc::update_organization_client),
        )
        .route(
            "/v1/organizations/{organization_id}/oidc/clients/{client_id}/rotate-secret",
            post(oidc::rotate_organization_client_secret),
        )
}

pub fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/oidc/authorize", get(oidc::authorize))
        .route("/v1/oidc/login", post(oidc::login))
        .route("/v1/oidc/consent", post(oidc::consent))
        .route("/v1/oidc/logout", post(oidc::logout))
        .route("/v1/oidc/token", post(oidc::token))
        .route("/v1/oidc/userinfo", get(oidc::userinfo))
        .route("/.well-known/openid-configuration", get(oidc::discovery))
}

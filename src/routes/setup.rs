use crate::handlers::setup::{
    setup_asset, setup_initialize, setup_page, setup_status, setup_status_page,
};
use crate::state::AppState;
use axum::routing::{get, post};
use axum::Router;

pub fn setup_routes() -> Router<AppState> {
    Router::new()
        .route("/setup", get(setup_page))
        .route("/setup/status-page", get(setup_status_page))
        .route("/setup/assets/{*path}", get(setup_asset))
        .route("/setup/status", get(setup_status))
        .route("/setup/initialize", post(setup_initialize))
}

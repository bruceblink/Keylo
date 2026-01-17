use axum::Router;
use axum::routing::get;
use crate::handlers::{index, protected};
use crate::routes;
use crate::state::AppState;

pub fn init_app_router() -> Router {
    let app_state = AppState::default();
    Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .merge(routes::auth::router())
        .with_state(app_state)
}
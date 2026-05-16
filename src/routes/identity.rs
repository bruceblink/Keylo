use crate::handlers::identity::{
    create_identity_source, get_identity_source, list_identity_sources, update_identity_source,
};
use crate::state::AppState;
use axum::routing::{get, post, put};
use axum::Router;

/// 管理员路由：统一身份源注册中心（需要 admin scope）
pub fn identity_admin_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/admin/identity-sources", get(list_identity_sources))
        .route("/v1/admin/identity-sources", post(create_identity_source))
        .route(
            "/v1/admin/identity-sources/{source_id}",
            get(get_identity_source),
        )
        .route(
            "/v1/admin/identity-sources/{source_id}",
            put(update_identity_source),
        )
}

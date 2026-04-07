use crate::handlers::service::{
    get_service, list_services, register_service, rotate_service_secret, service_introspect,
    service_token, update_service,
};
use crate::state::AppState;
use axum::routing::{get, post, put};
use axum::Router;

/// 公开路由：服务 Token 获取与 Token 内省
/// /v1/service/token    - 服务间认证，获取 JWT
/// /v1/service/introspect - 内省服务 Token（需要有效的 service_access Token）
pub fn service_public_routes() -> Router<AppState> {
    Router::new().route("/v1/service/token", post(service_token))
}

/// 需要服务 Token 保护的路由
/// /v1/service/introspect - 内省 Token（调用方本身必须携带合法 service Token）
pub fn service_introspect_routes() -> Router<AppState> {
    Router::new().route("/v1/service/introspect", post(service_introspect))
}

/// 管理员路由：服务客户端 CRUD（需要 admin scope）
pub fn service_admin_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/admin/services", get(list_services))
        .route("/v1/admin/services", post(register_service))
        .route("/v1/admin/services/{service_id}", get(get_service))
        .route("/v1/admin/services/{service_id}", put(update_service))
        .route(
            "/v1/admin/services/{service_id}/rotate-secret",
            post(rotate_service_secret),
        )
}

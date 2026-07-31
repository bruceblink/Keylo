use crate::handlers::identity::{
    begin_oidc_upstream_login, complete_oidc_upstream_login, create_identity_source,
    discover_oidc_upstream, get_identity_source, list_identity_sources,
    list_my_oidc_upstream_identities, list_oidc_identity_source_links,
    unlink_oidc_identity_source_link, unlink_oidc_upstream_identity, update_identity_source,
};
use crate::state::AppState;
use axum::routing::{delete, get, post, put};
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
        .route(
            "/v1/admin/identity-sources/{source_id}/oidc/discover",
            post(discover_oidc_upstream),
        )
        .route(
            "/v1/admin/identity-sources/{source_id}/links",
            get(list_oidc_identity_source_links),
        )
        .route(
            "/v1/admin/identity-sources/{source_id}/links/{user_id}",
            delete(unlink_oidc_identity_source_link),
        )
}

/// Public browser entry point for a registered upstream OIDC identity source.
pub fn identity_public_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/upstream/oidc/{source_name}/login",
            get(begin_oidc_upstream_login),
        )
        .route(
            "/v1/upstream/oidc/callback",
            get(complete_oidc_upstream_login),
        )
}

/// User-owned upstream identity operations; access is constrained by user authorization middleware.
pub fn identity_self_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/user/identity-sources/links",
            get(list_my_oidc_upstream_identities),
        )
        .route(
            "/v1/user/identity-sources/{source_id}/link",
            delete(unlink_oidc_upstream_identity),
        )
}

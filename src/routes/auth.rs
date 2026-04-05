use crate::handlers::user::register_user;
use crate::handlers::{
    auth_blacklist_token, auth_cleanup_audit_logs, auth_create_client, auth_get_audit_logs,
    auth_get_blacklisted_tokens, auth_list_clients, auth_logout, auth_me, auth_refresh,
    auth_rotate_client_secret, auth_token, auth_update_client,
};
use crate::state::AppState;
use axum::routing::{get, post, put};
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
        .route("/v1/admin/audit-logs", get(auth_get_audit_logs))
        .route(
            "/v1/admin/audit-logs/cleanup",
            post(auth_cleanup_audit_logs),
        )
        .route("/v1/admin/clients", get(auth_list_clients))
        .route("/v1/admin/clients", post(auth_create_client))
        .route("/v1/admin/clients/{client_id}", put(auth_update_client))
        .route(
            "/v1/admin/clients/{client_id}/rotate-secret",
            post(auth_rotate_client_secret),
        )
}

pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/v1/auth/register", post(register_user))
        .route("/v1/auth/token", post(auth_token))
        .route("/v1/auth/refresh", post(auth_refresh))
}

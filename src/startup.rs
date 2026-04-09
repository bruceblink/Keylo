use crate::config::Config;
use crate::handlers::{index, protected};
use crate::middleware::auth;
use crate::routes;
use crate::state::AppState;
use axum::middleware;
use axum::routing::get;
use axum::Router;
use redis::AsyncCommands;
use std::sync::Arc;

pub fn init_app_router() -> Router {
    let app_state = AppState::default();
    Router::new()
        .merge(routes::auth::public_router())
        .route("/", get(index))
        .route("/protected", get(protected))
        .merge(routes::auth::protected_router())
        .with_state(app_state)
}

pub fn init_app_router_with_config(config: Config) -> Router {
    let app_state = AppState::new(config, None);
    Router::new()
        .merge(routes::auth::public_router())
        .nest("/v1/auth/oauth", routes::oauth::oauth_public_routes())
        .route("/", get(index))
        .route("/protected", get(protected))
        .merge(routes::auth::protected_router())
        .with_state(app_state)
}

pub async fn init_app_router_with_db(
    config: Config,
    database_url: &str,
) -> Result<Router, anyhow::Error> {
    if config.is_production() {
        if config.jwt_using_default_dev_keys {
            anyhow::bail!(
                "JWT_PRIVATE_KEY_PEM/JWT_PUBLIC_KEY_PEM or corresponding *_PATH values must be set in production"
            );
        }
        let has_admin_id = std::env::var("ADMIN_CLIENT_ID").ok().is_some();
        let has_admin_secret = std::env::var("ADMIN_CLIENT_SECRET").ok().is_some();
        if !has_admin_id || !has_admin_secret {
            anyhow::bail!("ADMIN_CLIENT_ID and ADMIN_CLIENT_SECRET must be set in production");
        }
        if config.redis_url.is_none() {
            anyhow::bail!("REDIS_URL must be set in production");
        }
    }

    if config.is_production() {
        let redis_url = config.redis_url.as_deref().unwrap_or_default();
        let redis_client = redis::Client::open(redis_url)?;
        let mut conn = redis_client.get_multiplexed_tokio_connection().await?;
        let _: String = conn.ping().await?;
    }

    let db = crate::db::init_db_pool(database_url).await?;

    // Run migrations
    crate::db::run_migrations(&db).await?;
    tracing::info!("Database migrations completed");

    // Seed default clients
    crate::db::seed_default_clients(&db).await?;
    tracing::info!("Default clients seeded");

    // Cleanup old audit logs (best effort)
    match crate::db::cleanup_old_audit_logs(&db, config.audit_log_retention_days).await {
        Ok(deleted) => tracing::info!("Audit logs cleanup completed, deleted={}", deleted),
        Err(e) => tracing::warn!("Audit logs cleanup failed: {}", e),
    }

    let app_state = AppState::new(config, Some(Arc::new(db)));

    let public_routes = Router::new()
        .merge(routes::auth::public_router())
        .merge(routes::service::service_public_routes())
        .route("/", get(index))
        .nest("/v1/auth/oauth", routes::oauth::oauth_public_routes());

    let service_protected_routes = Router::new()
        .merge(routes::auth::service_integration_routes())
        .merge(routes::service::service_introspect_routes())
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth::service_auth_middleware,
        ));

    let protected_routes = Router::new()
        .route("/protected", get(protected))
        .merge(routes::auth::protected_router())
        .merge(routes::user::self_user_routes())
        .merge(
            routes::auth::admin_router()
                .route_layer(middleware::from_fn(auth::admin_scope_middleware)),
        )
        .nest(
            "/api/oauth",
            routes::oauth::oauth_admin_routes()
                .route_layer(middleware::from_fn(auth::admin_scope_middleware)),
        )
        .nest(
            "/api/rbac",
            routes::rbac::rbac_routes()
                .route_layer(middleware::from_fn(auth::admin_scope_middleware)),
        )
        .merge(
            routes::service::service_admin_routes()
                .route_layer(middleware::from_fn(auth::admin_scope_middleware)),
        )
        .merge(
            routes::user::admin_user_routes()
                .route_layer(middleware::from_fn(auth::admin_scope_middleware)),
        )
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth::auth_middleware,
        ));

    Ok(Router::new()
        .merge(public_routes)
        .merge(service_protected_routes)
        .merge(protected_routes)
        .with_state(app_state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use tower::{Service, ServiceExt};

    #[tokio::test]
    async fn test_index() {
        let app = init_app_router();

        // `Router` implements `tower::Service<Request<Body>>` so we can
        // call it like any tower service, no need to run an HTTP server.
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Welcome to the keylo :)");
    }

    // You can also spawn a server and talk to it like any other HTTP server:
    #[tokio::test]
    async fn the_real_deal() {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            axum::serve(listener, init_app_router())
                .await
                .unwrap_or_default();
        });

        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http();

        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://127.0.0.1:{port}"))
                    .header("Host", "localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Welcome to the keylo :)");
    }

    #[tokio::test]
    async fn with_into_make_service_with_connect_info() {
        let mut app = init_app_router()
            .layer(MockConnectInfo(SocketAddr::from(([0, 0, 0, 0], 3001))))
            .into_service();

        let request = Request::builder().uri("/").body(Body::empty()).unwrap();
        let response = app.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

use axum::Router;
use axum::routing::get;
use axum::middleware;
use std::sync::Arc;
use crate::config::Config;
use crate::handlers::{index, protected};
use crate::routes;
use crate::state::AppState;
use crate::middleware::auth;

pub fn init_app_router() -> Router {
    let app_state = AppState::default();
    Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .merge(routes::auth::router())
        .with_state(app_state)
}

pub fn init_app_router_with_config(config: Config) -> Router {
    let app_state = AppState::new(config, None);
    Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .merge(routes::auth::router())
        .with_state(app_state)
}

pub async fn init_app_router_with_db(config: Config, database_url: &str) -> Result<Router, anyhow::Error> {
    let db = crate::db::init_db_pool(database_url).await?;
    
    // Run migrations
    crate::db::run_migrations(&db).await?;
    tracing::info!("Database migrations completed");
    
    let app_state = AppState::new(config, Some(Arc::new(db)));
    
    Ok(Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .merge(routes::auth::router())
        .layer(middleware::from_fn_with_state(app_state.clone(), auth::auth_middleware))
        .with_state(app_state))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use axum::extract::connect_info::MockConnectInfo;
    use http_body_util::BodyExt;
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

        let request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let response = app.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

}
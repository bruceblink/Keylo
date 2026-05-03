use crate::config::Config;
use crate::handlers::{healthz, index, protected, readyz};
use crate::middleware::auth;
use crate::routes;
use crate::state::AppState;
use axum::middleware;
use axum::routing::get;
use axum::Router;
use redis::AsyncCommands;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};

pub fn init_app_router() -> Router {
    let app_state = AppState::new(Config::default(), None)
        .expect("Default Config must always produce valid JWT keys");
    Router::new()
        .merge(routes::auth::public_router())
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/", get(index))
        .route("/protected", get(protected))
        .merge(routes::auth::protected_router())
        .with_state(app_state)
}

pub fn init_app_router_with_config(config: Config) -> Router {
    let app_state = AppState::new(config, None)
        .expect("Failed to initialize AppState: invalid JWT key configuration");
    Router::new()
        .merge(routes::auth::public_router())
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
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
    if config.jwt_private_key_pem.trim().is_empty() || config.jwt_public_key_pem.trim().is_empty() {
        anyhow::bail!(
            "JWT_PRIVATE_KEY_PEM/JWT_PUBLIC_KEY_PEM or corresponding *_PATH values must be set"
        );
    }

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
    } else if config.jwt_using_default_dev_keys {
        tracing::warn!("⚠️  SECURITY WARNING: Using hardcoded development JWT keys. \
            Set JWT_PRIVATE_KEY_PEM / JWT_PUBLIC_KEY_PEM (or their *_PATH equivalents) \
            before deploying to production. These keys are public and MUST NOT be used in production.");
    }

    if config.is_production() {
        let redis_url = config.redis_url.as_deref().unwrap_or_default();
        let redis_client = redis::Client::open(redis_url)
            .map_err(|e| anyhow::anyhow!("Invalid REDIS_URL '{}': {}", redis_url, e))?;

        let mut redis_ready = false;
        let mut last_redis_err: Option<String> = None;
        for attempt in 1..=30 {
            match redis_client.get_multiplexed_async_connection().await {
                Ok(mut conn) => match conn.ping::<String>().await {
                    Ok(_) => {
                        redis_ready = true;
                        break;
                    }
                    Err(e) => {
                        last_redis_err = Some(e.to_string());
                    }
                },
                Err(e) => {
                    last_redis_err = Some(e.to_string());
                }
            }

            tracing::warn!(
                "Redis not ready (attempt {}/30, url={}): {}",
                attempt,
                redis_url,
                last_redis_err.as_deref().unwrap_or("unknown error")
            );
            sleep(Duration::from_secs(1)).await;
        }

        if !redis_ready {
            anyhow::bail!(
                "Redis connection failed after 30 attempts (url={}): {}",
                redis_url,
                last_redis_err.as_deref().unwrap_or("unknown error")
            );
        }
    }

    let db = {
        let mut connected: Option<sqlx::PgPool> = None;
        let mut last_db_err: Option<String> = None;

        for attempt in 1..=30 {
            match crate::db::init_db_pool(database_url).await {
                Ok(pool) => {
                    connected = Some(pool);
                    break;
                }
                Err(e) => {
                    last_db_err = Some(e.to_string());
                    tracing::warn!(
                        "Postgres not ready (attempt {}/30, url={}): {}",
                        attempt,
                        database_url,
                        last_db_err.as_deref().unwrap_or("unknown error")
                    );
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }

        connected.ok_or_else(|| {
            anyhow::anyhow!(
                "Postgres connection failed after 30 attempts (url={}): {}",
                database_url,
                last_db_err.as_deref().unwrap_or("unknown error")
            )
        })?
    };

    // Run migrations
    crate::db::run_migrations(&db).await?;
    tracing::info!("Database migrations completed");

    // Seed default clients
    crate::db::seed_default_clients(&db).await?;
    tracing::info!("Default clients seeded");

    // Optional super admin bootstrap
    crate::db::seed_super_admin_user(&db, &config).await?;
    tracing::info!("Super admin bootstrap checked");

    // 非生产环境下，若未配置管理客户端且未启用超级管理员引导，提示管理面可能不可用
    if !config.is_production() {
        let has_admin_client = crate::db::has_active_admin_client(&db)
            .await
            .unwrap_or(false);
        if !has_admin_client && !config.enable_super_admin_bootstrap {
            tracing::warn!(
                "No active admin client found and SUPER_ADMIN bootstrap is disabled. \
                 /v1/admin/token and admin management APIs may be unavailable."
            );
        }
    }

    // Cleanup old audit logs (best effort)
    match crate::db::cleanup_old_audit_logs(&db, config.audit_log_retention_days).await {
        Ok(deleted) => tracing::info!("Audit logs cleanup completed, deleted={}", deleted),
        Err(e) => tracing::warn!("Audit logs cleanup failed: {}", e),
    }

    let app_state = AppState::new(config, Some(Arc::new(db)))?;

    let public_routes = Router::new()
        .merge(routes::auth::public_router())
        .merge(routes::service::service_public_routes())
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/", get(index))
        .nest("/v1/auth/oauth", routes::oauth::oauth_public_routes());

    // service_integration_routes 需要 audience="admin-backend"，使用在 JWT 层严格校验 aud 的专用中间件
    let service_integration_routes = routes::auth::service_integration_routes()
        .route_layer(middleware::from_fn(
            auth::service_integration_authorization_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth::service_integration_auth_middleware,
        ));

    let service_protected_routes = Router::new()
        .merge(service_integration_routes)
        .merge(
            routes::service::service_introspect_routes().route_layer(middleware::from_fn(
                auth::service_read_authorization_middleware,
            )),
        )
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth::service_auth_middleware,
        ));

    let protected_routes = Router::new()
        .route("/protected", get(protected))
        .merge(routes::auth::protected_router())
        .merge(
            routes::user::self_user_routes()
                .route_layer(middleware::from_fn(auth::user_authorization_middleware)),
        )
        .merge(
            routes::auth::admin_router()
                .route_layer(middleware::from_fn(auth::admin_authorization_middleware)),
        )
        .nest(
            "/api/oauth",
            routes::oauth::oauth_admin_routes()
                .route_layer(middleware::from_fn(auth::admin_authorization_middleware)),
        )
        .nest(
            "/api/rbac",
            routes::rbac::rbac_routes()
                .route_layer(middleware::from_fn(auth::admin_authorization_middleware)),
        )
        .merge(
            routes::service::service_admin_routes()
                .route_layer(middleware::from_fn(auth::admin_authorization_middleware)),
        )
        .merge(
            routes::user::admin_user_routes()
                .route_layer(middleware::from_fn(auth::admin_authorization_middleware)),
        )
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth::auth_middleware,
        ));

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|origin, _| {
            // Only allow https origins (or localhost for dev)
            let s = origin.as_bytes();
            s.starts_with(b"https://") || s.starts_with(b"http://localhost")
        }))
        .allow_methods(AllowMethods::list([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ]))
        .allow_headers(AllowHeaders::mirror_request())
        .allow_credentials(true);

    Ok(Router::new()
        .merge(public_routes)
        .merge(service_protected_routes)
        .merge(protected_routes)
        .layer(cors)
        .with_state(app_state))
}

/// 测试专用：显式传入 admin 凭据，避免 std::env::set_var 的并发竞态。
/// 每次调用都会 upsert admin client，确保密码始终与传入参数一致。
pub async fn init_app_router_with_db_and_admin(
    config: Config,
    database_url: &str,
    admin_client_id: &str,
    admin_client_secret: &str,
) -> Result<Router, anyhow::Error> {
    let db = crate::db::init_db_pool(database_url).await?;
    crate::db::run_migrations(&db).await?;
    crate::db::seed_default_clients_with_admin(
        &db,
        Some(admin_client_id),
        Some(admin_client_secret),
    )
    .await?;
    crate::db::seed_super_admin_user(&db, &config).await?;

    let app_state = AppState::new(config, Some(Arc::new(db)))?;

    let public_routes = Router::new()
        .merge(routes::auth::public_router())
        .merge(routes::service::service_public_routes())
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/", get(index))
        .nest("/v1/auth/oauth", routes::oauth::oauth_public_routes());

    let service_integration_routes = routes::auth::service_integration_routes()
        .route_layer(middleware::from_fn(
            auth::service_integration_authorization_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth::service_integration_auth_middleware,
        ));

    let service_protected_routes = Router::new()
        .merge(service_integration_routes)
        .merge(
            routes::service::service_introspect_routes().route_layer(middleware::from_fn(
                auth::service_read_authorization_middleware,
            )),
        )
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth::service_auth_middleware,
        ));

    let protected_routes = Router::new()
        .route("/protected", get(protected))
        .merge(routes::auth::protected_router())
        .merge(
            routes::user::self_user_routes()
                .route_layer(middleware::from_fn(auth::user_authorization_middleware)),
        )
        .merge(
            routes::auth::admin_router()
                .route_layer(middleware::from_fn(auth::admin_authorization_middleware)),
        )
        .nest(
            "/api/oauth",
            routes::oauth::oauth_admin_routes()
                .route_layer(middleware::from_fn(auth::admin_authorization_middleware)),
        )
        .nest(
            "/api/rbac",
            routes::rbac::rbac_routes()
                .route_layer(middleware::from_fn(auth::admin_authorization_middleware)),
        )
        .merge(
            routes::service::service_admin_routes()
                .route_layer(middleware::from_fn(auth::admin_authorization_middleware)),
        )
        .merge(
            routes::user::admin_user_routes()
                .route_layer(middleware::from_fn(auth::admin_authorization_middleware)),
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

    const TEST_JWT_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCsrVdCePdLh6/8
Xazk597DtrPS2rRHG/T8M9kfIequXrlRaYhwQkHLoGLK0Pn2wBmW5Ep81M3CRHCJ
Jzosqs6MYLfk2fr0Iwra0iBkNQx2vwEWmSZ3KZ4wGGRrlQI45vXOOAA2J6a1I6Ik
t8bV9N21jQ/pYDpI9SyHLvvHutZmyZHp0PGHNainUEddHsUqPUgwNpDsBl+v9fLV
OChsB382RTfX5tSd9s7IqhFROlOoWqdZm6+jRzIpusCYoKda6fxeBPC00E5eZNsV
PDBKbASFOrLTPvInucys4NiXY23e3U+OiZ6hSpWwMSy95HQOkVo34KGFWV0ZgaBv
K79AgyvDAgMBAAECggEAHEvljj+LasWn+aeSIwq6LwE8E5QCUdrLeR63+EmTDxL3
tFciZB7/cDJurgSzyZMuPlNXv4AR3cFgXaFff51X7poU2Hw+Cw7JAxXG+BTXX4gq
Uf0z1/gqc4AzyItpC1ERu8Liif1SbMGTmwfAniQbxtoAXwKFWppOuzJgURkVdE9T
WNd+waklRNBNO7abQBfP/qptyfRgaiGWT8ZNAWvlrwEY3MPcONfb9cvrIj4Oo4wK
MANT/vQOjMkvovtgkDH31WVAWdHWFZc7Weoo0b1edgwgc/pjMUVBXiPj0Ui9YH12
xPFOd3b9jTXmKmt5neXNLHJI9AaRtFXSG88fIGax6QKBgQDuCMhZxElQIgY9HRrz
Un5oQIxJ2AtMDuqW44zyBBwMxVRDaWDj6i2JN8H39KGPqMRNEzTzSYGPxaSRLRpB
1eWtAFpaVIkf02ruCbo9rdsFLaMoJY1SmIwk1AKTZ7GIqB00hlEr83H2Vy/JrWmq
zxYqAVKTakL1TFxokAxzs7th2wKBgQC5tb+4VM835n7r/QMkJeHv7naTZU85qUSn
P8fewEljF6PndKThm8StBBRCW6B0uaUE1ESsEClPRjaFtPF/BhIlmCkxaWpI0DEr
jfr/4SE1OmzNMZznl3aI4pNmBJiHWWneQuTgdHue/0uPOifbAn7elqfcfjzrxD3X
7HEYGMHGOQKBgF7YDwR9inysYfH949wp9YYSmhNeSvoOQ3jFyEYyTv7jrXSCy4Fk
sKopFld3GNzF8RmI2qNJmZ8wsCbMYtbypGYvatDtOAn/Um7wX03uNQO2MHlxpQLR
F54g/7m+KmX6HlDsZ/FsOe9exALG3wCZLQqlpkJop69XssZTBzMe3T3bAoGAJDym
sF08IfhEA+BW4JLTx3GMia5XCzVQRCJZ6ckziLZwMRW9ppgyhGArY9dlM+GVpZ+V
1s1Agkt9EBICnXqdx+AtCYs8RgD51znZJFzVkgFYgaGQsFAJvSQZBusWqDJ2Sfxb
lMCl7px6LfR3GnEeOGjFUG0Bji+4sY1ddApApWECgYBVjoNyfgQ/1vvJB3ZDXRrV
OdInx2dqATy+v1XXzSmHSkkE59SpDBex0mgDpBKfn1GJDCXeb5U9MAB7oAtGi8iJ
jwC3vnjXgXp6i1O/s7YjI4kfHYFZvKrYnDmjc2Ns/G2LgQF8LlRj+MJ4PVOqCIjr
RNDrJSwOaC4JLXavN61F6g==
-----END PRIVATE KEY-----"#;

    const TEST_JWT_PUBLIC_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArK1XQnj3S4ev/F2s5Ofe
w7az0tq0Rxv0/DPZHyHqrl65UWmIcEJBy6BiytD59sAZluRKfNTNwkRwiSc6LKrO
jGC35Nn69CMK2tIgZDUMdr8BFpkmdymeMBhka5UCOOb1zjgANiemtSOiJLfG1fTd
tY0P6WA6SPUshy77x7rWZsmR6dDxhzWop1BHXR7FKj1IMDaQ7AZfr/Xy1TgobAd/
NkU31+bUnfbOyKoRUTpTqFqnWZuvo0cyKbrAmKCnWun8XgTwtNBOXmTbFTwwSmwE
hTqy0z7yJ7nMrODYl2Nt3t1PjomeoUqVsDEsveR0DpFaN+ChhVldGYGgbyu/QIMr
wwIDAQAB
-----END PUBLIC KEY-----"#;

    fn test_config() -> Config {
        let mut config = Config::from_env();
        config.jwt_private_key_pem = TEST_JWT_PRIVATE_KEY_PEM.to_string();
        config.jwt_public_key_pem = TEST_JWT_PUBLIC_KEY_PEM.to_string();
        config
    }

    #[tokio::test]
    async fn test_index() {
        let app = init_app_router_with_config(test_config());

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Welcome to the keylo :)");
    }

    #[tokio::test]
    async fn the_real_deal() {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            axum::serve(listener, init_app_router_with_config(test_config()))
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
        let mut app = init_app_router_with_config(test_config())
            .layer(MockConnectInfo(SocketAddr::from(([0, 0, 0, 0], 3001))))
            .into_service();

        let request = Request::builder().uri("/").body(Body::empty()).unwrap();
        let response = app.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

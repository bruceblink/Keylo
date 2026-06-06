use crate::config::{build_database_url, database_password_from_env_result, Config};
use crate::handlers::{favicon, healthz, index, protected, readyz};
use crate::middleware::{auth, http_log};
use crate::routes;
use crate::state::AppState;
use axum::http::HeaderValue;
use axum::middleware;
use axum::routing::get;
use axum::Router;
use redis::AsyncCommands;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};

const STARTUP_RETRY_ATTEMPTS: u32 = 30;
const STARTUP_RETRY_DELAY: Duration = Duration::from_secs(1);

fn redact_dsn(input: &str) -> String {
    if let Some((scheme, rest)) = input.split_once("://") {
        if let Some((_, tail)) = rest.split_once('@') {
            return format!("{}://***@{}", scheme, tail);
        }
    }
    input.to_string()
}

fn is_allowed_cors_origin(origin: &HeaderValue, allowed_origins: &[String]) -> bool {
    let Ok(origin_str) = origin.to_str() else {
        return false;
    };
    let Ok(uri) = origin_str.parse::<http::Uri>() else {
        return false;
    };

    if let Some(path_and_query) = uri.path_and_query() {
        if path_and_query.as_str() != "/" {
            return false;
        }
    }

    allowed_origins.iter().any(|allowed| allowed == origin_str)
}

fn cors_layer(cors_allowed_origins: Vec<String>) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin, _| {
            is_allowed_cors_origin(origin, &cors_allowed_origins)
        }))
        .allow_methods(AllowMethods::list([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ]))
        .allow_headers(AllowHeaders::mirror_request())
        .allow_credentials(true)
}

fn resolve_database_url(database_url: &str) -> Result<String, anyhow::Error> {
    Ok(build_database_url(
        database_url.to_string(),
        database_password_from_env_result().map_err(anyhow::Error::msg)?,
    ))
}

fn validate_database_startup_config(
    config: &Config,
    database_url: &str,
) -> Result<(), anyhow::Error> {
    let mut startup_config = config.clone();
    startup_config.database_url = database_url.to_string();
    startup_config
        .validate_for_database_startup()
        .map_err(anyhow::Error::msg)
}

fn warn_if_jwt_keys_were_generated(config: &Config) {
    if config.jwt_keys_generated {
        tracing::warn!(
            private_key_path = std::env::var("JWT_PRIVATE_KEY_PATH")
                .unwrap_or_else(|_| "./keys/private.pem".to_string()),
            public_key_path = std::env::var("JWT_PUBLIC_KEY_PATH")
                .unwrap_or_else(|_| "./keys/public.pem".to_string()),
            "JWT RSA key pair was generated because no key configuration was found"
        );
    }
}

async fn require_redis_ready_in_production(config: &Config) -> Result<(), anyhow::Error> {
    if !config.is_production() {
        return Ok(());
    }

    let redis_url = config.redis_url.as_deref().unwrap_or_default();
    let redis_url_log = redact_dsn(redis_url);
    let redis_client = redis::Client::open(redis_url)
        .map_err(|e| anyhow::anyhow!("Invalid Redis URL '{}': {}", redis_url_log, e))?;

    let mut last_redis_err: Option<String> = None;
    for attempt in 1..=STARTUP_RETRY_ATTEMPTS {
        match redis_client.get_multiplexed_async_connection().await {
            Ok(mut conn) => match conn.ping::<String>().await {
                Ok(_) => return Ok(()),
                Err(e) => last_redis_err = Some(e.to_string()),
            },
            Err(e) => last_redis_err = Some(e.to_string()),
        }

        tracing::warn!(
            "Redis not ready (attempt {}/30, url={}): {}",
            attempt,
            redis_url_log,
            last_redis_err.as_deref().unwrap_or("unknown error")
        );
        sleep(STARTUP_RETRY_DELAY).await;
    }

    anyhow::bail!(
        "Redis connection failed after 30 attempts (url={}): {}",
        redis_url_log,
        last_redis_err.as_deref().unwrap_or("unknown error")
    )
}

async fn connect_postgres_with_retry(database_url: &str) -> Result<sqlx::PgPool, anyhow::Error> {
    let mut last_db_err: Option<String> = None;
    let database_url_log = redact_dsn(database_url);

    for attempt in 1..=STARTUP_RETRY_ATTEMPTS {
        match crate::db::init_db_pool(database_url).await {
            Ok(pool) => return Ok(pool),
            Err(e) => {
                last_db_err = Some(e.to_string());
                tracing::warn!(
                    "Postgres not ready (attempt {}/30, url={}): {}",
                    attempt,
                    database_url_log,
                    last_db_err.as_deref().unwrap_or("unknown error")
                );
                sleep(STARTUP_RETRY_DELAY).await;
            }
        }
    }

    anyhow::bail!(
        "Postgres connection failed after 30 attempts (url={}): {}",
        database_url_log,
        last_db_err.as_deref().unwrap_or("unknown error")
    )
}

async fn initialize_database(pool: &sqlx::PgPool, config: &Config) -> Result<(), anyhow::Error> {
    crate::db::run_migrations(pool).await?;
    tracing::info!("Database migrations completed");

    crate::db::seed_default_clients(pool, config).await?;
    tracing::info!("Default clients seeded");

    crate::db::seed_super_admin_user(pool, config).await?;
    tracing::info!("Super admin bootstrap checked");

    warn_if_management_client_is_missing(pool, config).await;
    cleanup_audit_logs(pool, config.audit_log_retention_days).await;

    Ok(())
}

async fn warn_if_management_client_is_missing(pool: &sqlx::PgPool, config: &Config) {
    if config.is_production() {
        return;
    }

    let has_admin_client = crate::db::has_active_admin_client(pool)
        .await
        .unwrap_or(false);
    if !has_admin_client && !config.enable_super_admin_bootstrap {
        tracing::warn!(
            "No active admin client found and SUPER_ADMIN bootstrap is disabled. \
             /v1/admin/token and admin management APIs may be unavailable."
        );
    }
}

async fn cleanup_audit_logs(pool: &sqlx::PgPool, retention_days: i64) {
    match crate::db::cleanup_old_audit_logs(pool, retention_days).await {
        Ok(deleted) => tracing::info!("Audit logs cleanup completed, deleted={}", deleted),
        Err(e) => tracing::warn!("Audit logs cleanup failed: {}", e),
    }
}

fn base_public_routes(include_oauth: bool) -> Router<AppState> {
    let routes = Router::new()
        .merge(routes::auth::public_router())
        .merge(routes::authorization::authorization_routes())
        .merge(routes::service::service_public_routes())
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/favicon.ico", get(favicon))
        .route("/", get(index));

    if include_oauth {
        routes.nest("/v1/auth/oauth", routes::oauth::oauth_public_routes())
    } else {
        routes
    }
}

fn in_memory_protected_routes() -> Router<AppState> {
    Router::new()
        .route("/protected", get(protected))
        .merge(routes::auth::protected_router())
}

fn service_protected_routes(app_state: &AppState) -> Router<AppState> {
    // service_integration_routes requires audience="admin-backend"; the dedicated
    // middleware validates that audience at JWT decode time.
    let service_integration_routes = routes::auth::service_integration_routes()
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth::service_integration_authorization_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth::service_integration_auth_middleware,
        ));

    Router::new()
        .merge(service_integration_routes)
        .merge(routes::service::service_introspect_routes().route_layer(
            middleware::from_fn_with_state(
                app_state.clone(),
                auth::service_read_authorization_middleware,
            ),
        ))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth::service_auth_middleware,
        ))
}

fn protected_routes(app_state: &AppState) -> Router<AppState> {
    Router::new()
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
        .merge(
            routes::principal::principal_admin_routes()
                .route_layer(middleware::from_fn(auth::admin_authorization_middleware)),
        )
        .merge(
            routes::resource::resource_admin_routes()
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
            routes::identity::identity_admin_routes()
                .route_layer(middleware::from_fn(auth::admin_authorization_middleware)),
        )
        .merge(
            routes::user::admin_user_routes()
                .route_layer(middleware::from_fn(auth::admin_authorization_middleware)),
        )
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth::auth_middleware,
        ))
}

fn database_router(app_state: AppState, cors_allowed_origins: Vec<String>) -> Router {
    Router::new()
        .merge(base_public_routes(true))
        .merge(routes::setup::setup_routes())
        .merge(service_protected_routes(&app_state))
        .merge(protected_routes(&app_state))
        .layer(cors_layer(cors_allowed_origins))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            http_log::request_response_logging_middleware,
        ))
        .with_state(app_state)
}

pub fn init_app_router() -> Router {
    let config = Config::default();
    let cors_allowed_origins = config.cors_allowed_origins.clone();
    let app_state =
        AppState::new(config, None).expect("Default Config must always produce valid JWT keys");
    Router::new()
        .merge(base_public_routes(false))
        .merge(in_memory_protected_routes())
        .merge(routes::setup::setup_routes())
        .layer(cors_layer(cors_allowed_origins))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            http_log::request_response_logging_middleware,
        ))
        .with_state(app_state)
}

pub fn init_app_router_with_config(config: Config) -> Router {
    let cors_allowed_origins = config.cors_allowed_origins.clone();
    let app_state = AppState::new(config, None)
        .expect("Failed to initialize AppState: invalid JWT key configuration");
    Router::new()
        .merge(base_public_routes(true))
        .merge(in_memory_protected_routes())
        .merge(routes::setup::setup_routes())
        .layer(cors_layer(cors_allowed_origins))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            http_log::request_response_logging_middleware,
        ))
        .with_state(app_state)
}

pub async fn init_app_router_with_db(
    config: Config,
    database_url: &str,
) -> Result<Router, anyhow::Error> {
    let database_url = resolve_database_url(database_url)?;
    validate_database_startup_config(&config, &database_url)?;
    warn_if_jwt_keys_were_generated(&config);
    require_redis_ready_in_production(&config).await?;

    let db = connect_postgres_with_retry(&database_url).await?;
    initialize_database(&db, &config).await?;

    let cors_allowed_origins = config.cors_allowed_origins.clone();
    let app_state = AppState::new(config, Some(Arc::new(db)))?;
    Ok(database_router(app_state, cors_allowed_origins))
}

/// 测试专用：显式传入 admin 凭据，避免 std::env::set_var 的并发竞态。
/// 每次调用都会 upsert admin client，确保密码始终与传入参数一致。
pub async fn init_app_router_with_db_and_admin(
    config: Config,
    database_url: &str,
    admin_client_id: &str,
    admin_client_secret: &str,
) -> Result<Router, anyhow::Error> {
    validate_test_database_startup_config(&config)?;

    let database_url = resolve_database_url(database_url)?;
    let db = crate::db::init_db_pool(&database_url).await?;
    crate::db::run_migrations(&db).await?;
    crate::db::seed_default_clients_with_admin(
        &db,
        Some(admin_client_id),
        Some(admin_client_secret),
    )
    .await?;
    crate::db::seed_super_admin_user(&db, &config).await?;

    let cors_allowed_origins = config.cors_allowed_origins.clone();
    let app_state = AppState::new(config, Some(Arc::new(db)))?;
    Ok(database_router(app_state, cors_allowed_origins))
}

fn validate_test_database_startup_config(config: &Config) -> Result<(), anyhow::Error> {
    let mut validation_config = config.clone();
    validation_config.admin_client_id = Some("test-admin-client".to_string());
    validation_config.admin_client_secret = Some("test-admin-secret".to_string());
    if validation_config.database_url.trim().is_empty() {
        validation_config.database_url = "postgres://keylo_user@localhost:5432/keylo".to_string();
    }
    validation_config
        .validate_for_database_startup()
        .map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::default_cors_allowed_origins;
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
        Config {
            jwt_issuer: "keylo".to_string(),
            jwt_key_id: "keylo-rs256-1".to_string(),
            jwt_audiences: vec!["admin-backend".to_string(), "crawler".to_string()],
            jwt_private_key_pem: TEST_JWT_PRIVATE_KEY_PEM.to_string(),
            jwt_public_key_pem: TEST_JWT_PUBLIC_KEY_PEM.to_string(),
            jwt_keys_generated: false,
            database_url: String::new(),
            server_addr: "127.0.0.1".to_string(),
            server_port: 2345,
            environment: "development".to_string(),
            token_expiry_seconds: 900,
            refresh_token_expiry_seconds: 2_592_000,
            session_policy: "multi_session".to_string(),
            max_failed_login_attempts: 5,
            login_lockout_seconds: 300,
            auth_rate_limit_window_seconds: 60,
            auth_rate_limit_max_requests: 30,
            auth_global_rate_limit_max_requests: 300,
            trust_proxy_headers: false,
            cors_allowed_origins: default_cors_allowed_origins(),
            admin_client_id: Some("cli-admin-root".to_string()),
            admin_client_secret: Some("test-admin-secret".to_string()),
            redis_url: None,
            redis_key_prefix: "keylo".to_string(),
            audit_log_retention_days: 30,
            service_token_expiry_seconds: 3600,
            enable_super_admin_bootstrap: false,
            super_admin_username: None,
            super_admin_email: None,
            super_admin_password: None,
            log_to_file: false,
            log_dir: "./logs".to_string(),
            log_file_prefix: "keylo".to_string(),
            http_log_body_max_bytes: 8192,
            allow_in_memory_fallback: false,
            enable_setup_wizard: false,
            setup_keys_dir: "./keys".to_string(),
        }
    }

    #[test]
    fn config_loads_admin_client_credentials_from_environment() {
        std::env::set_var("ADMIN_CLIENT_ID", "env-admin-client");
        std::env::set_var("ADMIN_CLIENT_SECRET", "env-admin-secret");

        let config = Config::from_env();

        assert_eq!(config.admin_client_id.as_deref(), Some("env-admin-client"));
        assert_eq!(
            config.admin_client_secret.as_deref(),
            Some("env-admin-secret")
        );

        std::env::remove_var("ADMIN_CLIENT_ID");
        std::env::remove_var("ADMIN_CLIENT_SECRET");
    }

    #[test]
    fn cors_origin_validation_matrix() {
        let allowed_origins = test_config().cors_allowed_origins;

        assert!(is_allowed_cors_origin(
            &HeaderValue::from_static("http://localhost:5173"),
            &allowed_origins
        ));
        assert!(is_allowed_cors_origin(
            &HeaderValue::from_static("http://127.0.0.1:5173"),
            &allowed_origins
        ));

        assert!(!is_allowed_cors_origin(
            &HeaderValue::from_static("https://example.com"),
            &allowed_origins
        ));
        assert!(!is_allowed_cors_origin(
            &HeaderValue::from_static("http://localhost.evil.com"),
            &allowed_origins
        ));
        assert!(!is_allowed_cors_origin(
            &HeaderValue::from_static("http://127.0.0.1.evil.com"),
            &allowed_origins
        ));
        assert!(!is_allowed_cors_origin(
            &HeaderValue::from_static("http://example.com"),
            &allowed_origins
        ));
        assert!(!is_allowed_cors_origin(
            &HeaderValue::from_static("http://localhost:5173/path"),
            &allowed_origins
        ));
    }

    #[test]
    fn cors_origin_validation_allows_explicit_https_origin() {
        assert!(is_allowed_cors_origin(
            &HeaderValue::from_static("https://example.com"),
            &["https://example.com".to_string()]
        ));
        assert!(is_allowed_cors_origin(
            &HeaderValue::from_static("https://example.com:8443"),
            &["https://example.com:8443".to_string()]
        ));

        assert!(!is_allowed_cors_origin(
            &HeaderValue::from_static("https://example.com/path"),
            &["https://example.com".to_string()]
        ));
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
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["status"], "ok");
        assert_eq!(body["service"], "keylo");
    }

    #[tokio::test]
    async fn readiness_fails_without_database_unless_fallback_is_explicit() {
        let app = init_app_router_with_config(test_config());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn readiness_allows_disabled_database_when_fallback_is_explicit() {
        let mut config = test_config();
        config.allow_in_memory_fallback = true;
        config.redis_url = None;
        let app = init_app_router_with_config(config);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn in_memory_router_includes_service_token_route() {
        let app = init_app_router_with_config(test_config());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/service/token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"service_id":"","service_secret":"","audience":"admin-backend","scope":"read"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["status"], "ok");
        assert_eq!(body["service"], "keylo");
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

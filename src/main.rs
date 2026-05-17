//! JWT Authorization and Authentication Service (Keylo)
//!
//! Run with:
//! ```not_rust
//! JWT_PRIVATE_KEY_PATH=./keys/private.pem JWT_PUBLIC_KEY_PATH=./keys/public.pem cargo run
//! DATABASE_URL=postgres://user@localhost/keylo DATABASE_PASSWORD_ENC_FILE=./.secrets/.postgres_password.enc DATABASE_PASSWORD_KEY_FILE=./.secrets/.database_password.key cargo run
//! ```
//!
//! Quick instructions:
//!
//! - Get a user authorization token:
//!
//! ```bash
//! curl -s -X POST -H 'Content-Type: application/json' \
//!   -d '{"client_id":"alice","client_secret":"password123"}' \
//!   http://localhost:2345/v1/auth/token
//! ```
//!
//! - Get an admin management token:
//!
//! ```bash
//! curl -s -X POST -H 'Content-Type: application/json' \
//!   -d '{"client_id":"admin-console","client_secret":"admin-secret"}' \
//!   http://localhost:2345/v1/admin/token
//! ```
//!
//! - Get current user info (replace TOKEN with your access_token):
//!
//! ```bash
//! curl -s -H 'Authorization: Bearer TOKEN' \
//!   http://localhost:2345/v1/auth/me
//! ```
//!
//! - Logout:
//!
//! ```bash
//! curl -s -X POST -H 'Authorization: Bearer TOKEN' \
//!   http://localhost:2345/v1/auth/logout
//! ```
//!
//! ## Service-to-Service Authentication
//!
//! - Register a service (admin token required):
//!
//! ```bash
//! curl -s -X POST -H 'Content-Type: application/json' \
//!   -H 'Authorization: Bearer ADMIN_TOKEN' \
//!   -d '{"service_id":"order-svc","service_secret":"strong-secret","name":"Order Service",
//!        "allowed_scopes":["read","write"],"allowed_audiences":["inventory-svc","payment-svc"]}' \
//!   http://localhost:2345/v1/admin/services
//! ```
//!
//! - Obtain a service-to-service token:
//!
//! ```bash
//! curl -s -X POST -H 'Content-Type: application/json' \
//!   -d '{"service_id":"order-svc","service_secret":"strong-secret",
//!        "audience":"inventory-svc","scope":"read"}' \
//!   http://localhost:2345/v1/service/token
//! ```
//!
//! - Introspect a service token (requires a valid service token itself):
//!
//! ```bash
//! curl -s -X POST -H 'Content-Type: application/json' \
//!   -H 'Authorization: Bearer SERVICE_TOKEN' \
//!   -d '{"token":"TARGET_TOKEN"}' \
//!   http://localhost:2345/v1/service/introspect
//! ```

use keylo::config::Config;
use keylo::startup;
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    keylo::config::load_dotenv();

    // Load configuration
    let config = Config::from_env();

    // Initialize logging
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "keylo=debug,axum=info,tower_http=info".into());

    let _log_guard = if config.log_to_file {
        std::fs::create_dir_all(&config.log_dir).map_err(|e| {
            anyhow::anyhow!("Failed to create log directory '{}': {}", config.log_dir, e)
        })?;
        let file_appender =
            tracing_appender::rolling::daily(&config.log_dir, &config.log_file_prefix);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(non_blocking),
            )
            .init();
        Some(guard)
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
        None
    };

    tracing::info!("Starting Keylo service");
    tracing::info!("Environment: {}", config.environment);
    tracing::info!("Server: {}", config.server_url());
    tracing::info!(
        log_to_file = config.log_to_file,
        log_dir = %config.log_dir,
        log_file_prefix = %config.log_file_prefix,
        "Logging initialized with daily rolling file appender"
    );
    tracing::info!(
        setup_wizard_enabled = config.enable_setup_wizard,
        setup_token_configured = config.setup_token.is_some(),
        "Setup wizard configuration loaded"
    );
    tracing::info!(
        redis_configured = config.redis_url.is_some(),
        in_memory_fallback_allowed = config.allow_in_memory_fallback,
        "Runtime dependency configuration loaded"
    );

    if config.allow_in_memory_fallback {
        config
            .validate_for_in_memory_startup()
            .map_err(anyhow::Error::msg)?;
    } else {
        config
            .validate_for_database_startup()
            .map_err(anyhow::Error::msg)?;
    }

    // Try to initialize the app with database. In development we can fall back to in-memory mode,
    // but production must fail fast if startup requirements are not satisfied.
    let app = match startup::init_app_router_with_db(config.clone(), &config.database_url).await {
        Ok(app) => {
            tracing::info!("Database initialized successfully");
            app
        }
        Err(e) => {
            if config.is_production() || !config.allow_in_memory_fallback {
                tracing::error!("Failed to initialize Keylo: {}", e);
                return Err(anyhow::anyhow!("Failed to initialize Keylo: {}", e));
            }

            tracing::warn!(
                "Failed to initialize database: {}. Using in-memory mode.",
                e
            );
            startup::init_app_router_with_config(config.clone())
        }
    };

    // Bind to the configured address
    let addr = SocketAddr::from((
        config
            .server_addr
            .parse::<std::net::IpAddr>()
            .unwrap_or_else(|_| "127.0.0.1".parse().unwrap()),
        config.server_port,
    ));

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind to {}: {}", addr, e))?;

    tracing::info!("🚀 Server listening on {}", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Server error: {}", e))
}

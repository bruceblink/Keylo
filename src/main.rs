//! JWT Authorization and Authentication Service (Keylo)
//!
//! Run with:
//! ```not_rust
//! JWT_PRIVATE_KEY_PATH=./keys/private.pem JWT_PUBLIC_KEY_PATH=./keys/public.pem cargo run
//! DATABASE_URL=postgres://user:password@localhost/keylo cargo run
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
async fn main() {
    keylo::config::load_dotenv();

    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "keylo=debug,axum=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env();
    tracing::info!("Starting Keylo service");
    tracing::info!("Environment: {}", config.environment);
    tracing::info!("Server: {}", config.server_url());

    // Try to initialize the app with database. In development we can fall back to in-memory mode,
    // but production must fail fast if startup requirements are not satisfied.
    let app = match startup::init_app_router_with_db(config.clone(), &config.database_url).await {
        Ok(app) => {
            tracing::info!("Database initialized successfully");
            app
        }
        Err(e) => {
            if config.is_production() {
                panic!("Failed to initialize Keylo in production: {}", e);
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
        .unwrap_or_else(|_| panic!("Failed to bind to {}", addr));

    tracing::info!("🚀 Server listening on {}", addr);

    axum::serve(listener, app).await.expect("Server error");
}

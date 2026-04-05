//! JWT Authorization and Authentication Service (Keylo)
//!
//! Run with:
//! ```not_rust
//! JWT_SECRET=your-secret-key cargo run
//! DATABASE_URL=postgres://user:password@localhost/keylo cargo run
//! ```
//!
//! Quick instructions:
//!
//! - Get an authorization token:
//!
//! ```bash
//! curl -s -X POST -H 'Content-Type: application/json' \
//!   -d '{"client_id":"web","client_secret":"web-secret"}' \
//!   http://localhost:2345/v1/auth/token
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

use keylo::config::Config;
use keylo::startup;
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
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

    // Try to initialize the app with database, fallback to in-memory if DB is not available
    let app = match startup::init_app_router_with_db(config.clone(), &config.database_url).await {
        Ok(app) => {
            tracing::info!("Database initialized successfully");
            app
        }
        Err(e) => {
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

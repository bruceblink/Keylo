//! Example JWT authorization/authentication.
//!
//! Run with
//!
//! ```not_rust
//! JWT_SECRET=secret cargo run -p example-jwt
//! ```

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use keylo::startup::init_app_router;
// Quick instructions
//
// - get an authorization token:
//
// curl -s \
//     -w '\n' \
//     -H 'Content-Type: application/json' \
//     -d '{"client_id":"foo","client_secret":"bar"}' \
//     http://localhost:2345/v1/auth/token
//
// - visit the protected area using the authorized token
//
// curl -s \
//     -w '\n' \
//     -H 'Content-Type: application/json' \
//     -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjEwMDAwMDAwMDAwfQ.M3LAZmrzUkXDC1q5mSzFAs_kJrwuKz3jOoDmjJ0G4gM' \
//     http://localhost:2345/protected
//
// - try to visit the protected area using an invalid token
//
// curl -s \
//     -w '\n' \
//     -H 'Content-Type: application/json' \
//     -H 'Authorization: Bearer blahblahblah' \
//     http://localhost:2345/protected


#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // init app Router
    let app = init_app_router();

    let listener = tokio::net::TcpListener::bind("0.0.0.0:2345")
        .await
        .unwrap();
    tracing::info!("listening on {}", listener.local_addr().unwrap());
    let _ = axum::serve(listener, app).await;
}
use crate::errors::AuthError;
use crate::models::Claims;
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use redis::AsyncCommands;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

const READINESS_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

async fn setup_status_value(state: &AppState) -> Value {
    if !state.config.enable_setup_wizard {
        return json!({
            "enabled": false,
            "completed": null,
            "state": "disabled"
        });
    }

    let completed = match &state.db {
        Some(db) => crate::db::setup_completed(db.as_ref())
            .await
            .unwrap_or(false),
        None => false,
    };

    json!({
        "enabled": true,
        "completed": completed,
        "state": if completed { "completed" } else { "pending" }
    })
}

pub async fn index(State(state): State<AppState>) -> Response {
    if state.config.enable_setup_wizard {
        let setup_completed = match &state.db {
            Some(db) => crate::db::setup_completed(db.as_ref())
                .await
                .unwrap_or(false),
            None => false,
        };

        if !setup_completed {
            return Redirect::to("/setup").into_response();
        }
    }

    Json(json!({
        "service": "keylo",
        "status": "ok",
        "environment": state.config.environment,
        "setup": setup_status_value(&state).await,
        "endpoints": {
            "health": "/healthz",
            "readiness": "/readyz",
            "discovery": "/.well-known/keylo-configuration",
            "jwks": "/.well-known/jwks.json",
            "setup_status": "/setup/status"
        }
    }))
    .into_response()
}

pub async fn protected(claims: Claims) -> Result<String, AuthError> {
    // Send the protected data to the user
    Ok(format!(
        "Welcome to the protected area :)\nYour data:\n{claims}",
    ))
}

pub async fn healthz() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "keylo"
    }))
}

/// Expose process-local Prometheus metrics without labels that reveal request or identity data.
pub async fn metrics(State(state): State<AppState>) -> Response {
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        state.runtime_metrics.prometheus_text(),
    )
        .into_response()
}

pub async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// Return a stable public readiness error while retaining dependency details only in server logs.
/// Error codes and actions are safe for probes and operators; connection details stay in logs.
fn readiness_unavailable(
    checks: Value,
    error_code: &str,
    error: &str,
    next_action: &str,
    diagnostic: &str,
) -> (StatusCode, Json<Value>) {
    tracing::warn!(diagnostic, "Readiness probe failed");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "status": "error",
            "service": "keylo",
            "checks": checks,
            "error_code": error_code,
            "error": error,
            "next_action": next_action
        })),
    )
}

/// Probe database, setup, and configured Redis dependencies before reporting service readiness.
pub async fn readyz(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let redis_configured = state.config.redis_url.is_some();
    let mut checks = json!({
        "database": if state.config.allow_in_memory_fallback { "disabled" } else { "missing" },
        "redis": if redis_configured { "configured" } else { "disabled" },
        "setup": setup_status_value(&state).await
    });

    if let Some(db) = &state.db {
        let probe_started = Instant::now();
        let probe_result = tokio::time::timeout(
            READINESS_PROBE_TIMEOUT,
            sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(db.as_ref()),
        )
        .await;
        state.runtime_metrics.database_readiness_observed(
            probe_started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            matches!(&probe_result, Ok(Ok(_))),
        );
        match probe_result {
            Ok(Ok(_)) => checks["database"] = json!("ok"),
            Ok(Err(err)) => {
                return readiness_unavailable(
                    checks,
                    "database_not_ready",
                    "database not ready",
                    "Verify DATABASE_URL and database connectivity, then retry readiness.",
                    &err.to_string(),
                )
            }
            Err(_) => {
                return readiness_unavailable(
                    checks,
                    "database_not_ready",
                    "database not ready",
                    "Verify DATABASE_URL and database connectivity, then retry readiness.",
                    "database readiness probe timed out",
                )
            }
        }
    }

    if state.db.is_none() && !state.config.allow_in_memory_fallback {
        return readiness_unavailable(
            checks,
            "database_not_configured",
            "database not configured",
            "Set DATABASE_URL, or explicitly enable ALLOW_IN_MEMORY_FALLBACK for local-only development.",
            "database is not configured",
        );
    }

    if state.config.enable_setup_wizard && checks["setup"]["completed"] == json!(false) {
        return readiness_unavailable(
            checks,
            "setup_incomplete",
            "setup is not completed",
            "Open /setup and complete first-run initialization, then retry readiness.",
            "setup is not completed",
        );
    }

    if redis_configured {
        let Some(redis_client) = &state.redis_client else {
            return readiness_unavailable(
                checks,
                "redis_invalid_config",
                "redis configuration invalid",
                "Verify REDIS_URL or encrypted Redis credentials, then retry readiness.",
                "configured Redis URL could not be parsed",
            );
        };

        let probe_started = Instant::now();
        let probe_result = tokio::time::timeout(READINESS_PROBE_TIMEOUT, async {
            let mut conn = redis_client.get_multiplexed_async_connection().await?;
            conn.ping::<String>().await
        })
        .await;
        state.runtime_metrics.redis_readiness_observed(
            probe_started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            matches!(&probe_result, Ok(Ok(_))),
        );
        match probe_result {
            Ok(Ok(_)) => checks["redis"] = json!("ok"),
            Ok(Err(err)) => {
                return readiness_unavailable(
                    checks,
                    "redis_not_ready",
                    "redis not ready",
                    "Verify Redis host, port, credentials, and readiness, then retry.",
                    &err.to_string(),
                )
            }
            Err(_) => {
                return readiness_unavailable(
                    checks,
                    "redis_not_ready",
                    "redis not ready",
                    "Verify Redis host, port, credentials, and readiness, then retry readiness.",
                    "redis readiness probe timed out",
                )
            }
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "service": "keylo",
            "checks": checks
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::{readiness_unavailable, readyz};
    use crate::{config::Config, state::AppState};
    use axum::extract::State;
    use axum::http::StatusCode;
    use serde_json::json;

    #[test]
    fn readiness_error_does_not_expose_dependency_diagnostics() {
        let diagnostic = "connection failed for redis://keylo:secret@redis:6379/0";
        let (status, body) = readiness_unavailable(
            json!({"redis": "disabled"}),
            "redis_not_ready",
            "redis not ready",
            "Verify Redis host, port, credentials, and readiness, then retry.",
            diagnostic,
        );

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0["error_code"], "redis_not_ready");
        assert!(body.0["next_action"].as_str().unwrap().contains("Redis"));
        assert_eq!(body.0["error"], "redis not ready");
        assert!(!body.0.to_string().contains("secret"));
    }

    #[tokio::test]
    async fn readiness_rejects_an_invalid_configured_redis_url() {
        let config = Config {
            allow_in_memory_fallback: true,
            enable_setup_wizard: false,
            redis_url: Some("http://localhost:6379".to_string()),
            ..Config::default()
        };
        let state = AppState::new(config, None).expect("test state should use valid JWT keys");

        let (status, body) = readyz(State(state)).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0["error_code"], "redis_invalid_config");
        assert!(body.0["next_action"]
            .as_str()
            .unwrap()
            .contains("REDIS_URL"));
        assert_eq!(body.0["checks"]["redis"], "configured");
    }
}

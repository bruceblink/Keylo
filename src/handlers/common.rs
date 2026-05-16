use crate::errors::AuthError;
use crate::models::Claims;
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use redis::AsyncCommands;
use serde_json::{json, Value};

pub async fn index() -> Result<String, AuthError> {
    // Send the protected data to the user
    Ok("Welcome to the keylo :)".to_string())
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

pub async fn readyz(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let mut checks = json!({
        "database": if state.config.allow_in_memory_fallback { "disabled" } else { "missing" },
        "redis": "disabled"
    });

    if let Some(db) = &state.db {
        match sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(db.as_ref())
            .await
        {
            Ok(_) => checks["database"] = json!("ok"),
            Err(err) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "status": "error",
                        "service": "keylo",
                        "checks": checks,
                        "error": format!("database not ready: {}", err)
                    })),
                );
            }
        }
    }

    if state.db.is_none() && !state.config.allow_in_memory_fallback {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "error",
                "service": "keylo",
                "checks": checks,
                "error": "database not configured"
            })),
        );
    }

    if state.config.redis_url.is_some() {
        if let Some(redis_client) = &state.redis_client {
            match redis_client.get_multiplexed_async_connection().await {
                Ok(mut conn) => match conn.ping::<String>().await {
                    Ok(_) => checks["redis"] = json!("ok"),
                    Err(err) => {
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(json!({
                                "status": "error",
                                "service": "keylo",
                                "checks": checks,
                                "error": format!("redis not ready: {}", err)
                            })),
                        );
                    }
                },
                Err(err) => {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({
                            "status": "error",
                            "service": "keylo",
                            "checks": checks,
                            "error": format!("redis connection failed: {}", err)
                        })),
                    );
                }
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

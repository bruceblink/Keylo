use crate::errors::AuthError;
use crate::models::Claims;
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use redis::AsyncCommands;
use serde_json::{json, Value};

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

pub async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}

pub async fn readyz(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let mut checks = json!({
        "database": if state.config.allow_in_memory_fallback { "disabled" } else { "missing" },
        "redis": "disabled",
        "setup": setup_status_value(&state).await
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

    if state.config.enable_setup_wizard && checks["setup"]["completed"] == json!(false) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "error",
                "service": "keylo",
                "checks": checks,
                "error": "setup is not completed"
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

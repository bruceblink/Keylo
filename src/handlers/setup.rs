use crate::config::{build_database_url, database_password_from_env_result};
use crate::db;
use crate::errors::AuthError;
use crate::models::{
    SetupCheck, SetupEndpoints, SetupInitializeRequest, SetupInitializeResponse,
    SetupStatusResponse,
};
use crate::state::AppState;
use axum::extract::{Path as AxumPath, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::HeaderValue;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use redis::AsyncCommands;
use std::path::Path;
use std::time::Duration;

const SETUP_DIST_DIR: &str = "web/dist";
const DATABASE_CONNECTION_RETRY_MESSAGE: &str =
    "Database connection failed. Verify DATABASE_URL and database connectivity, then retry.";
const REDIS_CONNECTION_RETRY_MESSAGE: &str =
    "Redis connection failed. Verify Redis host, port, credentials, and readiness, then retry.";
const REDIS_INVALID_CONFIG_MESSAGE: &str =
    "Redis configuration is invalid. Verify Redis host, port, credentials, and encryption settings, then retry.";
const REDIS_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const PRODUCTION_GENERATED_JWT_KEYS_MESSAGE: &str =
    "Production requires explicitly configured persistent JWT RSA keys";

fn require_setup_enabled(state: &AppState) -> Result<(), AuthError> {
    if !state.config.enable_setup_wizard {
        return Err(AuthError::NotFound);
    }

    Ok(())
}

/// Build copy-paste-ready setup endpoints from the stable public OIDC issuer, not the bind address.
fn setup_endpoints(state: &AppState) -> SetupEndpoints {
    let base_url = state.config.oidc_issuer();
    SetupEndpoints {
        issuer: base_url.clone(),
        jwks_uri: format!("{}/.well-known/jwks.json", base_url),
        discovery_uri: format!("{}/.well-known/keylo-configuration", base_url),
        admin_token_endpoint: format!("{}/v1/admin/token", base_url),
        user_token_endpoint: format!("{}/v1/auth/token", base_url),
        service_token_endpoint: format!("{}/v1/service/token", base_url),
    }
}

fn check(
    key: &str,
    label: &str,
    ok: bool,
    required: bool,
    message: impl Into<String>,
) -> SetupCheck {
    SetupCheck {
        key: key.to_string(),
        label: label.to_string(),
        ok,
        required,
        message: message.into(),
    }
}

/// Keep anonymous setup diagnostics safe while retaining the detailed database error in server logs.
fn database_connection_failure_check(error: &str) -> SetupCheck {
    tracing::warn!(diagnostic = error, "Setup database check failed");
    check(
        "database_connection",
        "Database Connection",
        false,
        true,
        DATABASE_CONNECTION_RETRY_MESSAGE,
    )
}

/// Turn migration ledger state into a non-blocking setup check because initialization runs migrations.
fn migration_check(status: db::MigrationStatus) -> SetupCheck {
    let message = if status.current {
        format!("All {} database migrations are applied", status.applied)
    } else if status.applied == 0 {
        "Database migrations are pending; setup initialization will run them".to_string()
    } else {
        format!(
            "Database migrations are incomplete ({}/{} applied); run migrations before serving traffic",
            status.applied, status.expected
        )
    };
    check(
        "migrations",
        "Database Migrations",
        status.current,
        false,
        message,
    )
}

/// Hide migration query details from the anonymous setup response while leaving the check actionable.
fn migration_status_failure_check(error: &str) -> SetupCheck {
    tracing::warn!(diagnostic = error, "Setup migration status check failed");
    check(
        "migrations",
        "Database Migrations",
        false,
        false,
        "Migration status is unavailable; run migrations and retry setup.",
    )
}

/// Probe configured Redis with a short timeout and keep connection details out of anonymous setup responses.
async fn redis_check(state: &AppState, required: bool) -> SetupCheck {
    let configured = state
        .config
        .redis_url
        .as_deref()
        .is_some_and(|url| !url.trim().is_empty());
    if !configured {
        return check(
            "redis",
            "Redis",
            !required,
            required,
            if required {
                "Redis is required in production"
            } else {
                "Redis is optional outside production"
            },
        );
    }

    let Some(redis_client) = state.redis_client.as_ref() else {
        tracing::warn!("Setup Redis check found an invalid configured client");
        return check(
            "redis",
            "Redis",
            false,
            required,
            REDIS_INVALID_CONFIG_MESSAGE,
        );
    };

    let probe = tokio::time::timeout(REDIS_PROBE_TIMEOUT, async {
        let mut connection = redis_client.get_multiplexed_async_connection().await?;
        connection.ping::<String>().await
    })
    .await;

    match probe {
        Ok(Ok(_)) => check(
            "redis",
            "Redis",
            true,
            required,
            "Redis connection succeeded",
        ),
        Ok(Err(error)) => {
            tracing::warn!(diagnostic = %error, "Setup Redis check failed");
            check(
                "redis",
                "Redis",
                false,
                required,
                REDIS_CONNECTION_RETRY_MESSAGE,
            )
        }
        Err(_) => {
            tracing::warn!(
                timeout_seconds = REDIS_PROBE_TIMEOUT.as_secs(),
                "Setup Redis check timed out"
            );
            check(
                "redis",
                "Redis",
                false,
                required,
                "Redis connection check timed out. Verify Redis readiness and network access, then retry.",
            )
        }
    }
}

async fn database_pool_from_config(state: &AppState) -> Result<Option<sqlx::PgPool>, String> {
    if let Some(pool) = &state.db {
        return Ok(Some(pool.as_ref().clone()));
    }

    let database_url = state.config.database_url.trim();
    if database_url.is_empty() {
        return Ok(None);
    }

    let database_url = build_database_url(
        database_url.to_string(),
        database_password_from_env_result().map_err(|err| err.to_string())?,
    );
    db::init_db_pool(&database_url)
        .await
        .map(Some)
        .map_err(|err| err.to_string())
}

fn has_jwt_keys(state: &AppState) -> bool {
    !state.config.jwt_private_key_pem.trim().is_empty()
        && !state.config.jwt_public_key_pem.trim().is_empty()
}

/// Report whether the loaded RSA pair is usable for the current environment.
fn jwt_keys_check(state: &AppState) -> SetupCheck {
    if state.config.is_production() && state.config.jwt_keys_generated {
        return check(
            "jwt_keys",
            "JWT RSA Keys",
            false,
            true,
            PRODUCTION_GENERATED_JWT_KEYS_MESSAGE,
        );
    }

    let keys_ok = has_jwt_keys(state);
    check(
        "jwt_keys",
        "JWT RSA Keys",
        keys_ok,
        true,
        if keys_ok {
            "JWT private/public keys are configured"
        } else {
            "JWT private/public keys are missing"
        },
    )
}

async fn setup_completed(state: &AppState) -> bool {
    let Some(pool) = database_pool_from_config(state).await.ok().flatten() else {
        return false;
    };

    db::setup_completed(&pool).await.unwrap_or(false)
}

fn setup_page_html() -> Response {
    match std::fs::read_to_string(Path::new(SETUP_DIST_DIR).join("index.html")) {
        Ok(html) => Html(html).into_response(),
        Err(_) => Html(
            r#"<!doctype html><html><head><meta charset="utf-8"><title>Keylo Setup</title></head>
<body><h1>Keylo Setup UI is not built</h1><p>Run <code>cd web && npm install && npm run build</code>, or use <code>npm run dev</code> during frontend development.</p></body></html>"#,
        )
        .into_response(),
    }
}

pub async fn setup_page(State(state): State<AppState>) -> impl IntoResponse {
    if !state.config.enable_setup_wizard {
        return AuthError::NotFound.into_response();
    }

    if setup_completed(&state).await {
        return Redirect::to("/setup/status-page").into_response();
    }

    setup_page_html()
}

pub async fn setup_status_page(State(state): State<AppState>) -> impl IntoResponse {
    if !state.config.enable_setup_wizard {
        return AuthError::NotFound.into_response();
    }

    if !setup_completed(&state).await {
        return Redirect::to("/setup").into_response();
    }

    setup_page_html()
}

pub async fn setup_asset(
    State(state): State<AppState>,
    AxumPath(path): AxumPath<String>,
) -> Response {
    if !state.config.enable_setup_wizard {
        return AuthError::NotFound.into_response();
    }

    if path.contains("..") || path.starts_with('/') || path.starts_with('\\') {
        return AuthError::NotFound.into_response();
    }

    let asset_path = Path::new(SETUP_DIST_DIR).join("assets").join(&path);
    let Ok(bytes) = std::fs::read(&asset_path) else {
        return AuthError::NotFound.into_response();
    };

    let content_type = match asset_path.extension().and_then(|ext| ext.to_str()) {
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    };

    let mut response = bytes.into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

pub async fn setup_status(
    State(state): State<AppState>,
) -> Result<Json<SetupStatusResponse>, AuthError> {
    require_setup_enabled(&state)?;
    let completed_before_auth = setup_completed(&state).await;

    let database_url_ok = !state.config.database_url.trim().is_empty();
    let redis_required = state.config.is_production();
    let admin_id_configured = state
        .config
        .admin_client_id
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let admin_secret_configured = state
        .config
        .admin_client_secret
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());

    let redis_status_check = redis_check(&state, redis_required).await;
    let mut checks = vec![
        check(
            "database_url",
            "Database URL",
            database_url_ok,
            true,
            if database_url_ok {
                "DATABASE_URL is configured"
            } else {
                "DATABASE_URL is missing"
            },
        ),
        redis_status_check,
        jwt_keys_check(&state),
        check(
            "admin_client_config",
            "Admin Client Config",
            admin_id_configured,
            false,
            if admin_id_configured && admin_secret_configured {
                "Admin client credentials are configured for automatic seed"
            } else if admin_id_configured {
                "Admin client secret can be provided during setup initialization"
            } else {
                "Admin client ID can be provided during setup initialization"
            },
        ),
    ];

    let mut completed = completed_before_auth;
    match database_pool_from_config(&state).await {
        Ok(Some(pool)) => {
            checks.push(check(
                "database_connection",
                "Database Connection",
                true,
                true,
                "Database connection succeeded",
            ));
            match db::migration_status(&pool).await {
                Ok(status) => checks.push(migration_check(status)),
                Err(err) => checks.push(migration_status_failure_check(&err.to_string())),
            }
            let admin_exists = db::has_active_admin_client(&pool).await.unwrap_or(false);
            checks.push(check(
                "admin_client_exists",
                "Admin Client Exists",
                admin_exists,
                false,
                if admin_exists {
                    "At least one active admin client exists"
                } else {
                    "No active admin client exists yet"
                },
            ));
            completed = db::setup_completed(&pool).await.unwrap_or(false);
        }
        Ok(None) => checks.push(check(
            "database_connection",
            "Database Connection",
            false,
            true,
            "Database URL is missing",
        )),
        Err(err) => checks.push(database_connection_failure_check(&err)),
    }

    Ok(Json(SetupStatusResponse {
        enabled: true,
        completed,
        environment: state.config.environment.clone(),
        admin_client_id_configured: admin_id_configured,
        admin_client_secret_configured: admin_secret_configured,
        checks,
        endpoints: setup_endpoints(&state),
    }))
}

fn normalized_required(field_name: &str, value: Option<String>) -> Result<String, AuthError> {
    let Some(value) = value else {
        return Err(AuthError::InvalidRequest(format!(
            "{field_name} is required"
        )));
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AuthError::InvalidRequest(format!(
            "{field_name} is required"
        )));
    }

    Ok(trimmed.to_string())
}

fn first_non_blank(primary: Option<String>, fallback: Option<&str>) -> Option<String> {
    primary
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            fallback
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
        })
}

pub async fn setup_initialize(
    State(state): State<AppState>,
    Json(payload): Json<SetupInitializeRequest>,
) -> Result<Json<SetupInitializeResponse>, AuthError> {
    require_setup_enabled(&state)?;

    if setup_completed(&state).await {
        return Err(AuthError::Forbidden);
    }

    if state.config.is_production() {
        state
            .config
            .validate_for_setup_initialization()
            .map_err(AuthError::InvalidRequest)?;
    }

    let admin_client_id = normalized_required(
        "admin_client_id",
        first_non_blank(
            payload.admin_client_id,
            state.config.admin_client_id.as_deref(),
        ),
    )?;
    let admin_client_secret = normalized_required(
        "admin_client_secret",
        first_non_blank(
            payload.admin_client_secret,
            state.config.admin_client_secret.as_deref(),
        ),
    )?;

    let pool = database_pool_from_config(&state)
        .await
        .map_err(AuthError::DatabaseError)?
        .ok_or_else(|| AuthError::InvalidRequest("DATABASE_URL is required".to_string()))?;

    db::run_migrations(&pool)
        .await
        .map_err(|err| AuthError::DatabaseError(err.to_string()))?;

    // Validate the loaded key pair before taking the session-scoped advisory lock.
    // This keeps a rejected setup request retryable when non-production key loading
    // or production configuration is incomplete.
    if !has_jwt_keys(&state) {
        return Err(AuthError::InvalidRequest(
            "JWT keys are missing; Keylo should auto-generate them during startup".to_string(),
        ));
    }

    let setup_lock = db::try_acquire_setup_initialization_lock(&pool)
        .await
        .map_err(|err| AuthError::DatabaseError(err.to_string()))?
        .ok_or_else(|| {
            AuthError::Conflict("Setup initialization is already running".to_string())
        })?;

    match db::setup_completed(&pool).await {
        Ok(true) => {
            setup_lock
                .release()
                .await
                .map_err(|err| AuthError::DatabaseError(err.to_string()))?;
            return Err(AuthError::Forbidden);
        }
        Ok(false) => {}
        Err(error) => {
            if let Err(release_error) = setup_lock.release().await {
                tracing::error!(
                    diagnostic = %release_error,
                    "Failed to release setup initialization lock after status check failure"
                );
            }
            return Err(AuthError::DatabaseError(error.to_string()));
        }
    }

    // Always attempt to release the session-scoped lock, including when seeding or
    // marking setup complete fails, so a later retry is not permanently blocked.
    let initialization_result = async {
        db::seed_default_clients_with_admin(
            &pool,
            Some(admin_client_id.as_str()),
            Some(admin_client_secret.as_str()),
        )
        .await
        .map_err(|err| AuthError::DatabaseError(err.to_string()))?;
        db::mark_setup_completed(&pool)
            .await
            .map_err(|err| AuthError::DatabaseError(err.to_string()))?;
        Ok::<(), AuthError>(())
    }
    .await;
    let release_result = setup_lock
        .release()
        .await
        .map_err(|err| AuthError::DatabaseError(err.to_string()));
    match initialization_result {
        Err(error) => {
            if let Err(release_error) = release_result {
                tracing::error!(
                    diagnostic = %release_error,
                    "Failed to release setup initialization lock after initialization failure"
                );
            }
            return Err(error);
        }
        Ok(()) => release_result?,
    }

    Ok(Json(SetupInitializeResponse {
        completed: true,
        admin_client_id,
        endpoints: setup_endpoints(&state),
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        database_connection_failure_check, first_non_blank, jwt_keys_check, migration_check,
        migration_status_failure_check, redis_check, setup_endpoints,
        PRODUCTION_GENERATED_JWT_KEYS_MESSAGE, REDIS_INVALID_CONFIG_MESSAGE,
    };
    use crate::{config::Config, state::AppState};

    #[test]
    fn setup_endpoints_use_public_oidc_issuer() {
        let config = Config {
            oidc_public_issuer: Some("https://identity.example.com".to_string()),
            server_addr: "0.0.0.0".to_string(),
            server_port: 2345,
            ..Config::default()
        };
        let state = AppState::new(config, None).expect("test state should use valid JWT keys");

        let endpoints = setup_endpoints(&state);

        assert_eq!(endpoints.issuer, "https://identity.example.com");
        assert_eq!(
            endpoints.jwks_uri,
            "https://identity.example.com/.well-known/jwks.json"
        );
        assert_eq!(
            endpoints.discovery_uri,
            "https://identity.example.com/.well-known/keylo-configuration"
        );
        assert_eq!(
            endpoints.admin_token_endpoint,
            "https://identity.example.com/v1/admin/token"
        );
    }

    #[test]
    fn database_connection_check_hides_diagnostic_details() {
        let check = database_connection_failure_check(
            "failed to connect to postgres://keylo:secret@db.internal:5432/keylo",
        );

        assert!(!check.ok);
        assert_eq!(check.message, super::DATABASE_CONNECTION_RETRY_MESSAGE);
        assert!(check.message.contains("DATABASE_URL"));
        assert!(!check.message.contains("secret"));
    }

    #[test]
    fn migration_check_is_visible_without_blocking_initialization() {
        let check = migration_check(crate::db::MigrationStatus {
            applied: 0,
            expected: 32,
            current: false,
        });

        assert_eq!(check.key, "migrations");
        assert!(!check.ok);
        assert!(!check.required);
        assert!(check.message.contains("will run them"));
    }

    #[test]
    fn migration_status_failure_is_safe_and_actionable() {
        let check = migration_status_failure_check(
            "relation _sqlx_migrations does not exist for postgres://keylo:secret@db/keylo",
        );

        assert!(!check.ok);
        assert!(!check.required);
        assert!(check.message.contains("run migrations"));
        assert!(!check.message.contains("secret"));
    }

    #[tokio::test]
    async fn redis_check_marks_unconfigured_redis_optional_outside_production() {
        let config = Config {
            environment: "test".to_string(),
            redis_url: None,
            ..Config::default()
        };
        let state = AppState::new(config, None).expect("test state should use valid JWT keys");

        let check = redis_check(&state, false).await;

        assert!(check.ok);
        assert!(!check.required);
        assert_eq!(check.message, "Redis is optional outside production");
    }

    #[tokio::test]
    async fn redis_check_reports_invalid_config_without_exposing_url() {
        let config = Config {
            environment: "production".to_string(),
            redis_url: Some("http://keylo:secret@redis:6379".to_string()),
            ..Config::default()
        };
        let state = AppState::new(config, None).expect("test state should use valid JWT keys");

        let check = redis_check(&state, true).await;

        assert!(!check.ok);
        assert!(check.required);
        assert_eq!(check.message, REDIS_INVALID_CONFIG_MESSAGE);
        assert!(!check.message.contains("secret"));
    }

    #[test]
    fn jwt_keys_check_rejects_generated_keys_in_production() {
        let config = Config {
            environment: "production".to_string(),
            jwt_keys_generated: true,
            ..Config::default()
        };
        let state = AppState::new(config, None).expect("test state should use valid JWT keys");

        let check = jwt_keys_check(&state);

        assert!(!check.ok);
        assert!(check.required);
        assert_eq!(check.message, PRODUCTION_GENERATED_JWT_KEYS_MESSAGE);
    }

    #[test]
    fn first_non_blank_uses_configured_fallback_for_blank_payload() {
        assert_eq!(
            first_non_blank(Some("   ".to_string()), Some("Configured#123")).as_deref(),
            Some("Configured#123")
        );
    }

    #[test]
    fn first_non_blank_prefers_submitted_value() {
        assert_eq!(
            first_non_blank(Some("Submitted#123".to_string()), Some("Configured#123")).as_deref(),
            Some("Submitted#123")
        );
    }
}

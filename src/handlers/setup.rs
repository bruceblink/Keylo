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
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use axum_extra::headers::{authorization::Bearer, Authorization};
use axum_extra::TypedHeader;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::rand_core::OsRng;
use rsa::RsaPrivateKey;
use std::path::Path;

const SETUP_DIST_DIR: &str = "web/dist";

fn require_setup_enabled(state: &AppState) -> Result<(), AuthError> {
    if !state.config.enable_setup_wizard {
        return Err(AuthError::NotFound);
    }

    Ok(())
}

fn authorize_setup(
    state: &AppState,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
) -> Result<(), AuthError> {
    let Some(expected) = state.config.setup_token.as_deref() else {
        if state.config.is_production() {
            return Err(AuthError::Unauthorized);
        }
        return Ok(());
    };

    let Some(TypedHeader(Authorization(actual))) = bearer else {
        return Err(AuthError::Unauthorized);
    };

    if actual.token() != expected {
        return Err(AuthError::Unauthorized);
    }

    Ok(())
}

fn setup_endpoints(state: &AppState) -> SetupEndpoints {
    let base_url = state.config.server_url();
    SetupEndpoints {
        issuer: state.config.jwt_issuer.clone(),
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

async fn setup_completed(state: &AppState) -> bool {
    let Some(pool) = database_pool_from_config(state).await.ok().flatten() else {
        return false;
    };

    db::setup_completed(&pool).await.unwrap_or(false)
}

pub async fn setup_page(State(state): State<AppState>) -> impl IntoResponse {
    if !state.config.enable_setup_wizard {
        return AuthError::NotFound.into_response();
    }

    match std::fs::read_to_string(Path::new(SETUP_DIST_DIR).join("index.html")) {
        Ok(html) => Html(html).into_response(),
        Err(_) => Html(
            r#"<!doctype html><html><head><meta charset="utf-8"><title>Keylo Setup</title></head>
<body><h1>Keylo Setup UI is not built</h1><p>Run <code>cd web && npm install && npm run build</code>, or use <code>npm run dev</code> during frontend development.</p></body></html>"#,
        )
        .into_response(),
    }
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
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
) -> Result<Json<SetupStatusResponse>, AuthError> {
    require_setup_enabled(&state)?;
    authorize_setup(&state, bearer)?;

    let database_url_ok = !state.config.database_url.trim().is_empty();
    let redis_required = state.config.is_production();
    let redis_ok = state
        .config
        .redis_url
        .as_deref()
        .is_some_and(|url| !url.trim().is_empty());
    let jwt_keys_ok = has_jwt_keys(&state);
    let admin_config_ok = state
        .config
        .admin_client_id
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        && state
            .config
            .admin_client_secret
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());

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
        check(
            "redis",
            "Redis",
            redis_ok || !redis_required,
            redis_required,
            if redis_ok {
                "REDIS_URL is configured"
            } else if redis_required {
                "REDIS_URL is required in production"
            } else {
                "REDIS_URL is optional outside production"
            },
        ),
        check(
            "jwt_keys",
            "JWT RSA Keys",
            jwt_keys_ok,
            true,
            if jwt_keys_ok {
                "JWT private/public keys are configured"
            } else {
                "JWT private/public keys are missing"
            },
        ),
        check(
            "admin_client_config",
            "Admin Client Config",
            admin_config_ok,
            true,
            if admin_config_ok {
                "Admin client credentials are configured"
            } else {
                "Admin client credentials are missing"
            },
        ),
    ];

    let mut completed = false;
    match database_pool_from_config(&state).await {
        Ok(Some(pool)) => {
            checks.push(check(
                "database_connection",
                "Database Connection",
                true,
                true,
                "Database connection succeeded",
            ));
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
        Err(err) => checks.push(check(
            "database_connection",
            "Database Connection",
            false,
            true,
            format!("Database connection failed: {err}"),
        )),
    }

    Ok(Json(SetupStatusResponse {
        enabled: true,
        completed,
        environment: state.config.environment.clone(),
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

fn generate_rsa_key_pair(keys_dir: &str) -> Result<(), AuthError> {
    let dir = Path::new(keys_dir);
    std::fs::create_dir_all(dir).map_err(|err| {
        AuthError::InternalServerError(format!("Failed to create setup keys dir: {err}"))
    })?;

    let private_path = dir.join("private.pem");
    let public_path = dir.join("public.pem");
    if private_path.exists() || public_path.exists() {
        return Err(AuthError::Conflict(
            "RSA key files already exist; remove them or disable generate_rsa_keys".to_string(),
        ));
    }

    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).map_err(|err| {
        AuthError::InternalServerError(format!("Failed to generate RSA private key: {err}"))
    })?;
    let public_key = private_key.to_public_key();
    let private_pem = private_key.to_pkcs8_pem(LineEnding::LF).map_err(|err| {
        AuthError::InternalServerError(format!("Failed to encode RSA private key: {err}"))
    })?;
    let public_pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|err| {
            AuthError::InternalServerError(format!("Failed to encode RSA public key: {err}"))
        })?;

    std::fs::write(private_path, private_pem.as_bytes()).map_err(|err| {
        AuthError::InternalServerError(format!("Failed to write RSA private key: {err}"))
    })?;
    std::fs::write(public_path, public_pem.as_bytes()).map_err(|err| {
        AuthError::InternalServerError(format!("Failed to write RSA public key: {err}"))
    })?;

    Ok(())
}

pub async fn setup_initialize(
    State(state): State<AppState>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    Json(payload): Json<SetupInitializeRequest>,
) -> Result<Json<SetupInitializeResponse>, AuthError> {
    require_setup_enabled(&state)?;
    authorize_setup(&state, bearer)?;

    if setup_completed(&state).await {
        return Err(AuthError::Forbidden);
    }

    if state.config.is_production() {
        state
            .config
            .validate_for_database_startup()
            .map_err(AuthError::InvalidRequest)?;
    }

    let admin_client_id = normalized_required(
        "admin_client_id",
        payload
            .admin_client_id
            .or_else(|| state.config.admin_client_id.as_deref().map(str::to_string)),
    )?;
    let admin_client_secret = normalized_required(
        "admin_client_secret",
        payload.admin_client_secret.or_else(|| {
            state
                .config
                .admin_client_secret
                .as_deref()
                .map(str::to_string)
        }),
    )?;

    let pool = database_pool_from_config(&state)
        .await
        .map_err(AuthError::DatabaseError)?
        .ok_or_else(|| AuthError::InvalidRequest("DATABASE_URL is required".to_string()))?;

    db::run_migrations(&pool)
        .await
        .map_err(|err| AuthError::DatabaseError(err.to_string()))?;

    let generated_rsa_keys = payload.generate_rsa_keys.unwrap_or(false);
    if generated_rsa_keys {
        generate_rsa_key_pair(&state.config.setup_keys_dir)?;
    } else if !has_jwt_keys(&state) {
        return Err(AuthError::InvalidRequest(
            "JWT keys are missing; provide JWT key config or set generate_rsa_keys=true"
                .to_string(),
        ));
    }

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

    Ok(Json(SetupInitializeResponse {
        completed: true,
        generated_rsa_keys,
        keys_dir: state.config.setup_keys_dir.clone(),
        admin_client_id,
        endpoints: setup_endpoints(&state),
    }))
}

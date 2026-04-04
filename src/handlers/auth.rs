use crate::errors::AuthError;
use crate::models::{AuthBody, AuthPayload, Claims, MeResponse};
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use chrono::Utc;
use jsonwebtoken::{encode, Header};
use serde_json::json;
use crate::utils;

pub async fn auth_token(
    State(state): State<AppState>,
    Json(payload): Json<AuthPayload>,
) -> Result<Json<AuthBody>, AuthError> {
    // Check if the user sent the credentials
    if payload.client_id.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }
    
    // Validate client credentials
    if !state.validate_client(&payload.client_id, &payload.client_secret) {
        return Err(AuthError::WrongCredentials);
    }

    let now = Utc::now().timestamp();

    let claims = Claims {
        sub: format!("client:{}", payload.client_id),
        iss: "keylo".to_string(),
        aud: "admin-backend".to_string(),
        scope: vec!["read".into(), "write".into()],
        iat: now,
        exp: now + state.config.token_expiry_seconds,
        jti: utils::generate_jti(),
    };
    
    // Create the authorization token
    let token = encode(&Header::default(), &claims, &state.jwt_keys.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    // Send the authorized token
    Ok(Json(AuthBody::new(token)))
}

pub async fn auth_logout(
    State(_state): State<AppState>,
    claims: Claims,
) -> Result<Json<serde_json::Value>, AuthError> {
    // In a real application, you would:
    // 1. Add the token to a blacklist
    // 2. Revoke the session from the database
    // 3. Clear any cached data
    
    tracing::info!("User {} logged out", claims.sub);
    
    Ok(Json(json!({
        "message": "Successfully logged out",
        "sub": claims.sub,
    })))
}

pub async fn auth_me(
    claims: Claims,
) -> Result<Json<MeResponse>, AuthError> {
    Ok(Json(MeResponse {
        sub: claims.sub,
        scope: claims.scope,
        aud: claims.aud,
        exp: claims.exp,
        iss: claims.iss,
        jti: claims.jti,
    }))
}
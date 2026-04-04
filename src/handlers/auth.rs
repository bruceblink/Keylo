use crate::errors::AuthError;
use crate::models::{AuthBody, AuthPayload, Claims, MeResponse, RefreshTokenRequest};
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

    // Create access token claims
    let access_claims = Claims {
        sub: format!("client:{}", payload.client_id),
        iss: "keylo".to_string(),
        aud: "admin-backend".to_string(),
        scope: vec!["read".into(), "write".into()],
        iat: now,
        exp: now + state.config.token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "access".to_string(),
    };
    
    // Create refresh token claims
    let refresh_claims = Claims {
        sub: format!("client:{}", payload.client_id),
        iss: "keylo".to_string(),
        aud: "admin-backend".to_string(),
        scope: vec!["refresh".into()],
        iat: now,
        exp: now + state.config.refresh_token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "refresh".to_string(),
    };
    
    // Create the authorization tokens
    let access_token = encode(&Header::default(), &access_claims, &state.jwt_keys.encoding)
        .map_err(|_| AuthError::TokenCreation)?;
    
    let refresh_token = encode(&Header::default(), &refresh_claims, &state.jwt_keys.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    // Store refresh token in database
    if let Some(db) = &state.db {
        crate::db::create_refresh_token(db, &refresh_claims.jti, &payload.client_id, &refresh_token, refresh_claims.exp)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to create refresh token".to_string()))?;
    } else {
        return Err(AuthError::DatabaseError("Database not available".to_string()));
    }

    // Send the authorized tokens
    Ok(Json(AuthBody::new(access_token, refresh_token, state.config.token_expiry_seconds)))
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

pub async fn auth_refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<AuthBody>, AuthError> {
    // Check if refresh token exists and is not revoked
    let (token_id, client_id) = if let Some(db) = &state.db {
        match crate::db::validate_refresh_token(db, &payload.refresh_token).await {
            Ok(Some((id, client_id))) => (id, client_id),
            _ => return Err(AuthError::InvalidToken),
        }
    } else {
        return Err(AuthError::DatabaseError("Database not available".to_string()));
    };

    let now = Utc::now().timestamp();

    // Create new access token claims
    let access_claims = Claims {
        sub: format!("client:{}", client_id),
        iss: "keylo".to_string(),
        aud: "admin-backend".to_string(),
        scope: vec!["read".into(), "write".into()],
        iat: now,
        exp: now + state.config.token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "access".to_string(),
    };

    // Create new refresh token claims
    let new_refresh_claims = Claims {
        sub: format!("client:{}", client_id),
        iss: "keylo".to_string(),
        aud: "admin-backend".to_string(),
        scope: vec!["refresh".into()],
        iat: now,
        exp: now + state.config.refresh_token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "refresh".to_string(),
    };

    // Create new tokens
    let access_token = encode(&Header::default(), &access_claims, &state.jwt_keys.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    let new_refresh_token = encode(&Header::default(), &new_refresh_claims, &state.jwt_keys.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    // Revoke old refresh token
    if let Some(db) = &state.db {
        crate::db::revoke_refresh_token(db, &token_id)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to revoke refresh token".to_string()))?;
    }

    // Store new refresh token
    if let Some(db) = &state.db {
        crate::db::create_refresh_token(db, &new_refresh_claims.jti, &client_id, &new_refresh_token, new_refresh_claims.exp)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to create refresh token".to_string()))?;
    }

    Ok(Json(AuthBody::new(access_token, new_refresh_token, state.config.token_expiry_seconds)))
}
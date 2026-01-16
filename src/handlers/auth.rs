use crate::errors::AuthError;
use crate::models::{AuthBody, AuthPayload, Claims, MeResponse, KEYS};
use axum::Json;
use chrono::Utc;
use jsonwebtoken::{encode, Header};
use uuid::Uuid;

pub async fn auth_token(Json(payload): Json<AuthPayload>) -> Result<Json<AuthBody>, AuthError> {
    // Check if the user sent the credentials
    if payload.client_id.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }
    // Here you can check the user credentials from a database
    if payload.client_id != "foo" || payload.client_secret != "bar" {
        return Err(AuthError::WrongCredentials);
    }

    let now = Utc::now().timestamp();

    let claims = Claims {
        sub: format!("client:{}", payload.client_id),
        iss: "keylo".to_string(),
        aud: "admin-backend".to_string(),
        scope: vec!["internal".into(), "write".into()],
        iat: now,
        exp: now + 900, // 15 minutes
        jti: Uuid::new_v4().to_string(),
    };
    // Create the authorization token
    let token = encode(&Header::default(), &claims, &KEYS.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    // Send the authorized token
    Ok(Json(AuthBody::new(token)))
}

pub async fn auth_logout(Json(_payload): Json<AuthPayload>) -> Result<Json<AuthBody>, AuthError> {
    todo!()
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
    }))
}
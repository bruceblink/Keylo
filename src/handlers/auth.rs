use chrono::{Duration, Utc};
use axum::Json;
use jsonwebtoken::{encode, Header};
use crate::errors::AuthError;
use crate::models::{AuthBody, AuthPayload, Claims, KEYS};

pub async fn auth_token(Json(payload): Json<AuthPayload>) -> Result<Json<AuthBody>, AuthError> {
    // Check if the user sent the credentials
    if payload.client_id.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }
    // Here you can check the user credentials from a database
    if payload.client_id != "foo" || payload.client_secret != "bar" {
        return Err(AuthError::WrongCredentials);
    }

    let now = Utc::now();
    let exp = now + Duration::minutes(15);

    let claims = Claims {
        sub: "client:admin-backend".to_string(),
        scope: vec![],
        exp: exp.timestamp(),
        iss: "keylo".to_string(),
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

pub async fn auth_me(Json(_payload): Json<AuthPayload>) -> Result<Json<AuthBody>, AuthError> {
    todo!()
}
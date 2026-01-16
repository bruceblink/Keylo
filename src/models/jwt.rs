use std::fmt::Display;
use std::sync::LazyLock;
use axum::extract::FromRequestParts;
use axum::RequestPartsExt;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use axum_extra::TypedHeader;
use http::request::Parts;
use jsonwebtoken::{decode, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize};
use crate::errors::AuthError;

pub static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    Keys::new(secret.as_bytes())
});


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject：身份主体
    /// user:xxx | client:xxx
    pub sub: String,

    /// Issuer：签发方
    pub iss: String,

    /// Audience：token 适用对象
    /// admin-backend | crawler | *
    pub aud: String,

    /// Scope：权限集合（核心）
    pub scope: Vec<String>,

    /// Expiration time (unix timestamp)
    pub exp: i64,

    /// Issued at
    pub iat: i64,

    /// JWT ID（为吊销、审计预留）
    pub jti: String,
}

impl Display for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sub: {}\nScop: {:?}", self.sub, self.scope)
    }
}

impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        // Decode the user data
        let token_data = decode::<Claims>(bearer.token(), &KEYS.decoding, &Validation::default())
            .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

#[derive(Clone)]
pub struct Keys {
    pub encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}
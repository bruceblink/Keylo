use crate::errors::AuthError;
use crate::state::AppState;
use axum::extract::FromRequestParts;
use axum::RequestPartsExt;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use http::request::Parts;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use tracing::warn;

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

    /// Token 类型：access_token 或 refresh_token
    pub token_type: String,

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

impl FromRequestParts<AppState> for Claims {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        // Decode the user data
        let mut validation = Validation::default();
        validation.set_audience(&["admin-backend", "crawler"]);

        let token_data =
            match decode::<Claims>(bearer.token(), &state.jwt_keys.decoding, &validation) {
                Ok(data) => data,
                Err(err) => {
                    match *err.kind() {
                        ErrorKind::InvalidToken => warn!("JWT decode failed: invalid token"),
                        ErrorKind::InvalidSignature => {
                            warn!("JWT decode failed: invalid signature")
                        }
                        ErrorKind::ExpiredSignature => warn!("JWT decode failed: token expired"),
                        ErrorKind::InvalidIssuer => warn!("JWT decode failed: invalid issuer"),
                        ErrorKind::InvalidAudience => warn!("JWT decode failed: invalid audience"),
                        _ => warn!("JWT decode failed: {:?}", err),
                    }
                    return Err(AuthError::InvalidToken);
                }
            };
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

    pub fn decode_token(&self, token: &str) -> Result<Claims, AuthError> {
        let mut validation = Validation::default();
        validation.set_audience(&["admin-backend", "crawler"]);

        decode::<Claims>(token, &self.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|err| match err.kind() {
                ErrorKind::ExpiredSignature => AuthError::ExpiredToken,
                ErrorKind::InvalidSignature => AuthError::InvalidToken,
                _ => AuthError::InvalidToken,
            })
    }
}

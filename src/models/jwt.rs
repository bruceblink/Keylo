use crate::config::Config;
use crate::errors::AuthError;
use crate::state::AppState;
use axum::extract::FromRequestParts;
use axum::RequestPartsExt;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http::request::Parts;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject：身份主体
    /// user:xxx | client:xxx
    pub sub: String,

    /// User ID（users表主键）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// Keylo 2.0 unified Principal ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,

    /// Keylo 2.0 Principal type: user | service | client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_type: Option<String>,

    /// Issuer：签发方
    pub iss: String,

    /// Audience：token 适用对象
    /// admin-backend | crawler | *
    pub aud: String,

    /// Scope：权限集合（核心）
    pub scope: Vec<String>,

    /// Role：授权角色
    #[serde(default, deserialize_with = "deserialize_roles")]
    pub role: Vec<String>,

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
        write!(
            f,
            "Sub: {}\nScop: {:?}\nRole: {:?}",
            self.sub, self.scope, self.role
        )
    }
}

impl Claims {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope.iter().any(|value| value == scope)
    }

    pub fn has_audience(&self, audience: &str) -> bool {
        self.aud == audience || self.aud == "*"
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.role.iter().any(|value| value == role)
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RolesField {
    One(String),
    Many(Vec<String>),
}

fn deserialize_roles<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let parsed = Option::<RolesField>::deserialize(deserializer)?;
    Ok(match parsed {
        Some(RolesField::One(value)) => vec![value],
        Some(RolesField::Many(values)) => values,
        None => Vec::new(),
    })
}

impl FromRequestParts<AppState> for Claims {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(claims) = parts.extensions.get::<Claims>() {
            return Ok(claims.clone());
        }

        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;

        state.jwt_keys.decode_token(bearer.token())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub alg: String,
    pub kid: String,
    pub n: String,
    pub e: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksDocument {
    pub keys: Vec<Jwk>,
}

#[derive(Clone)]
pub struct Keys {
    pub encoding: EncodingKey,
    decoding: DecodingKey,
    algorithm: Algorithm,
    issuer: String,
    audiences: Vec<String>,
    key_id: String,
    jwks: JwksDocument,
}

impl Keys {
    pub fn from_config(config: &Config) -> Result<Self, String> {
        let encoding = EncodingKey::from_rsa_pem(config.jwt_private_key_pem.as_bytes())
            .map_err(|err| format!("invalid RSA private key: {err}"))?;
        let decoding = DecodingKey::from_rsa_pem(config.jwt_public_key_pem.as_bytes())
            .map_err(|err| format!("invalid RSA public key: {err}"))?;

        let public_key = RsaPublicKey::from_public_key_pem(&config.jwt_public_key_pem)
            .map_err(|err| format!("failed to parse RSA public key for JWKS: {err}"))?;
        let modulus = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let exponent = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        Ok(Self {
            encoding,
            decoding,
            algorithm: Algorithm::RS256,
            issuer: config.jwt_issuer.clone(),
            audiences: config.jwt_audiences.clone(),
            key_id: config.jwt_key_id.clone(),
            jwks: JwksDocument {
                keys: vec![Jwk {
                    kty: "RSA".to_string(),
                    use_: "sig".to_string(),
                    alg: "RS256".to_string(),
                    kid: config.jwt_key_id.clone(),
                    n: modulus,
                    e: exponent,
                }],
            },
        })
    }

    pub fn sign_token<T: Serialize>(&self, claims: &T) -> Result<String, AuthError> {
        let mut header = Header::new(self.algorithm);
        header.kid = Some(self.key_id.clone());

        encode(&header, claims, &self.encoding).map_err(|_| AuthError::TokenCreation)
    }

    pub fn jwks(&self) -> JwksDocument {
        self.jwks.clone()
    }

    pub fn decode_token(&self, token: &str) -> Result<Claims, AuthError> {
        let mut validation = Validation::new(self.algorithm);
        let audiences = self
            .audiences
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        validation.set_audience(&audiences);
        validation.set_issuer(&[self.issuer.as_str()]);

        decode::<Claims>(token, &self.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|err| match err.kind() {
                ErrorKind::ExpiredSignature => AuthError::ExpiredToken,
                ErrorKind::InvalidAudience => AuthError::InvalidAudience,
                _ => {
                    match err.kind() {
                        ErrorKind::InvalidToken => warn!("JWT decode failed: invalid token"),
                        ErrorKind::InvalidSignature => {
                            warn!("JWT decode failed: invalid signature")
                        }
                        ErrorKind::InvalidIssuer => warn!("JWT decode failed: invalid issuer"),
                        ErrorKind::InvalidAudience => {
                            warn!("JWT decode failed: invalid audience")
                        }
                        _ => warn!("JWT decode failed: {:?}", err),
                    }
                    AuthError::InvalidToken
                }
            })
    }

    pub fn decode_service_token(
        &self,
        token: &str,
    ) -> Result<crate::models::service::ServiceClaims, AuthError> {
        let mut validation = Validation::new(self.algorithm);
        validation.validate_aud = false;
        validation.set_issuer(&[self.issuer.as_str()]);

        let claims =
            decode::<crate::models::service::ServiceClaims>(token, &self.decoding, &validation)
                .map(|data| data.claims)
                .map_err(|err| match err.kind() {
                    ErrorKind::ExpiredSignature => AuthError::ExpiredToken,
                    _ => AuthError::InvalidToken,
                })?;

        // Ensure aud field is present and non-empty; precise audience enforcement
        // is performed by the middleware layer (ensure_service_claims).
        if claims.aud.trim().is_empty() {
            return Err(AuthError::InvalidToken);
        }

        Ok(claims)
    }

    /// Like [`decode_service_token`] but also validates that the token's `aud` matches
    /// `expected_audience` at the JWT level, providing defense-in-depth for call sites
    /// that know the expected audience at decode time.
    pub fn decode_service_token_for_audience(
        &self,
        token: &str,
        expected_audience: &str,
    ) -> Result<crate::models::service::ServiceClaims, AuthError> {
        let mut validation = Validation::new(self.algorithm);
        validation.set_audience(&[expected_audience]);
        validation.set_issuer(&[self.issuer.as_str()]);

        decode::<crate::models::service::ServiceClaims>(token, &self.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|err| match err.kind() {
                ErrorKind::ExpiredSignature => AuthError::ExpiredToken,
                _ => AuthError::InvalidToken,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn claims_extractor_reuses_middleware_claims() {
        let state = AppState::default();
        let claims = Claims {
            sub: "user:alice".to_string(),
            uid: Some("user-1".to_string()),
            principal_id: Some("user-user-1".to_string()),
            principal_type: Some("user".to_string()),
            iss: state.config.jwt_issuer.clone(),
            aud: "admin-backend".to_string(),
            scope: vec!["read".to_string(), "write".to_string()],
            role: vec!["user".to_string()],
            token_type: "access".to_string(),
            exp: chrono::Utc::now().timestamp() + 60,
            iat: chrono::Utc::now().timestamp(),
            jti: "test-jti".to_string(),
        };

        let request = http::Request::builder().uri("/").body(()).unwrap();
        let (mut parts, _) = request.into_parts();
        parts.extensions.insert(claims.clone());

        let extracted =
            <Claims as FromRequestParts<AppState>>::from_request_parts(&mut parts, &state)
                .await
                .unwrap();

        assert_eq!(extracted.sub, claims.sub);
        assert_eq!(extracted.uid, claims.uid);
        assert_eq!(extracted.principal_id, claims.principal_id);
        assert_eq!(extracted.jti, claims.jti);
    }
}

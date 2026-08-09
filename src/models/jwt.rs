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
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::sync::{Arc, RwLock};
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

    /// Active organization context selected after a live membership check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,

    /// One-time customer-support grant that bounds a dedicated support token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_support_grant_id: Option<String>,

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
struct KeyPair {
    key_id: String,
    private_key_pem: Option<String>,
    public_key_pem: String,
    encoding: Option<EncodingKey>,
    decoding: DecodingKey,
    jwk: Jwk,
    expires_at: Option<i64>,
}

impl KeyPair {
    fn from_pem(
        key_id: String,
        private_key_pem: Option<&str>,
        public_key_pem: &str,
        expires_at: Option<i64>,
    ) -> Result<Self, String> {
        let decoding = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
            .map_err(|err| format!("invalid RSA public key: {err}"))?;
        let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
            .map_err(|err| format!("failed to parse RSA public key for JWKS: {err}"))?;
        let encoding = private_key_pem
            .map(|pem| {
                EncodingKey::from_rsa_pem(pem.as_bytes())
                    .map_err(|err| format!("invalid RSA private key: {err}"))
            })
            .transpose()?;
        Ok(Self {
            key_id: key_id.clone(),
            private_key_pem: private_key_pem.map(str::to_string),
            public_key_pem: public_key_pem.to_string(),
            encoding,
            decoding,
            jwk: Jwk {
                kty: "RSA".to_string(),
                use_: "sig".to_string(),
                alg: "RS256".to_string(),
                kid: key_id,
                n: URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
                e: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
            },
            expires_at,
        })
    }

    fn is_live(&self, now: i64) -> bool {
        self.expires_at.is_none_or(|expires_at| expires_at > now)
    }
}

#[derive(Clone)]
pub struct Keys {
    active: Arc<RwLock<KeyPair>>,
    passive: Arc<RwLock<Vec<KeyPair>>>,
    algorithm: Algorithm,
    issuer: String,
    audiences: Vec<String>,
}

impl Keys {
    /// Load the active signer and any configured passive verifier from startup configuration.
    pub fn from_config(config: &Config) -> Result<Self, String> {
        let active = KeyPair::from_pem(
            config.jwt_key_id.clone(),
            Some(&config.jwt_private_key_pem),
            &config.jwt_public_key_pem,
            None,
        )?;
        let passive = match (
            config.jwt_passive_key_id.as_deref(),
            config.jwt_passive_public_key_pem.as_deref(),
        ) {
            (Some(key_id), Some(public_key_pem)) => vec![KeyPair::from_pem(
                key_id.to_string(),
                config.jwt_passive_private_key_pem.as_deref(),
                public_key_pem,
                Some(chrono::Utc::now().timestamp() + config.jwt_key_overlap_seconds),
            )?],
            (None, None) => Vec::new(),
            _ => {
                return Err(
                    "JWT_PASSIVE_KEY_ID and JWT_PASSIVE_PUBLIC_KEY_PEM/PATH must be configured together"
                        .to_string(),
                )
            }
        };
        Ok(Self {
            active: Arc::new(RwLock::new(active)),
            passive: Arc::new(RwLock::new(passive)),
            algorithm: Algorithm::RS256,
            issuer: config.jwt_issuer.clone(),
            audiences: config.jwt_audiences.clone(),
        })
    }

    pub fn sign_token<T: Serialize>(&self, claims: &T) -> Result<String, AuthError> {
        let mut header = Header::new(self.algorithm);
        let active = self.active.read().map_err(|_| AuthError::TokenCreation)?;
        header.kid = Some(active.key_id.clone());
        let encoding = active.encoding.as_ref().ok_or(AuthError::TokenCreation)?;
        encode(&header, claims, encoding).map_err(|_| AuthError::TokenCreation)
    }

    pub fn jwks(&self) -> JwksDocument {
        let now = chrono::Utc::now().timestamp();
        let active = self.active.read().expect("JWT active key lock poisoned");
        let passive = self.passive.read().expect("JWT passive key lock poisoned");
        let mut keys = vec![active.jwk.clone()];
        keys.extend(
            passive
                .iter()
                .filter(|key| key.is_live(now))
                .map(|key| key.jwk.clone()),
        );
        JwksDocument { keys }
    }

    pub fn active_key_id(&self) -> String {
        self.active
            .read()
            .expect("JWT active key lock poisoned")
            .key_id
            .clone()
    }

    pub fn active_key_material(&self) -> (String, String) {
        let active = self.active.read().expect("JWT active key lock poisoned");
        (
            active
                .private_key_pem
                .clone()
                .expect("JWT active key must retain private material"),
            active.public_key_pem.clone(),
        )
    }

    pub fn passive_key_material(&self, key_id: &str) -> Option<(String, String)> {
        self.passive
            .read()
            .expect("JWT passive key lock poisoned")
            .iter()
            .find(|key| key.key_id == key_id && key.is_live(chrono::Utc::now().timestamp()))
            .and_then(|key| Some((key.private_key_pem.clone()?, key.public_key_pem.clone())))
    }

    pub fn passive_key_ids(&self) -> Vec<String> {
        self.passive
            .read()
            .expect("JWT passive key lock poisoned")
            .iter()
            .filter(|key| key.is_live(chrono::Utc::now().timestamp()))
            .map(|key| key.key_id.clone())
            .collect()
    }

    /// Promote a new signing pair and retain the previous pair for verification overlap.
    pub fn rotate(
        &self,
        key_id: &str,
        private_key_pem: &str,
        public_key_pem: &str,
        overlap_seconds: i64,
    ) -> Result<(), String> {
        if key_id.trim().is_empty() {
            return Err("JWT key id must not be empty".to_string());
        }
        if overlap_seconds <= 0 {
            return Err("JWT key overlap must be positive".to_string());
        }
        let mut active = self
            .active
            .write()
            .map_err(|_| "JWT active key lock poisoned".to_string())?;
        if active.key_id == key_id {
            return Err("JWT key id must differ from the active key".to_string());
        }
        let mut previous = active.clone();
        previous.expires_at = Some(chrono::Utc::now().timestamp() + overlap_seconds);
        let next = KeyPair::from_pem(
            key_id.to_string(),
            Some(private_key_pem),
            public_key_pem,
            None,
        )?;
        let mut passive = self
            .passive
            .write()
            .map_err(|_| "JWT passive key lock poisoned".to_string())?;
        *active = next;
        *passive = vec![previous];
        Ok(())
    }

    /// Retire one passive key before its normal overlap expiry.
    pub fn retire_passive(&self, key_id: &str) -> bool {
        let mut passive = self.passive.write().expect("JWT passive key lock poisoned");
        let before = passive.len();
        passive.retain(|key| key.key_id != key_id);
        passive.len() != before
    }

    /// Restore the passive private key as the signer while retaining the current signer for overlap.
    pub fn rollback(&self, key_id: &str, overlap_seconds: i64) -> Result<(), String> {
        if overlap_seconds <= 0 {
            return Err("JWT key overlap must be positive".to_string());
        }
        let mut active = self
            .active
            .write()
            .map_err(|_| "JWT active key lock poisoned".to_string())?;
        let mut passive = self
            .passive
            .write()
            .map_err(|_| "JWT passive key lock poisoned".to_string())?;
        let index = passive
            .iter()
            .position(|key| key.key_id == key_id && key.is_live(chrono::Utc::now().timestamp()))
            .ok_or_else(|| "JWT passive key not found or expired".to_string())?;
        if passive[index].encoding.is_none() {
            return Err("JWT passive key has no private key for rollback".to_string());
        }
        let mut previous = active.clone();
        previous.expires_at = Some(chrono::Utc::now().timestamp() + overlap_seconds);
        let mut promoted = passive.remove(index);
        promoted.expires_at = None;
        *active = promoted;
        passive.clear();
        passive.push(previous);
        Ok(())
    }

    /// Select the active or still-live passive key by JWT `kid` before verifying claims.
    fn decode_with_key<T: DeserializeOwned>(
        &self,
        token: &str,
        validation: &Validation,
    ) -> Result<jsonwebtoken::TokenData<T>, jsonwebtoken::errors::Error> {
        let header = jsonwebtoken::decode_header(token)?;
        let now = chrono::Utc::now().timestamp();
        let active = self.active.read().expect("JWT active key lock poisoned");
        if header.kid.is_none() || header.kid.as_deref() == Some(active.key_id.as_str()) {
            return decode(token, &active.decoding, validation);
        }
        let passive = self.passive.read().expect("JWT passive key lock poisoned");
        let Some(key) = passive
            .iter()
            .find(|key| header.kid.as_deref() == Some(key.key_id.as_str()) && key.is_live(now))
        else {
            return Err(jsonwebtoken::errors::Error::from(ErrorKind::InvalidToken));
        };
        decode(token, &key.decoding, validation)
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

        self.decode_with_key::<Claims>(token, &validation)
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

        let claims = self
            .decode_with_key::<crate::models::service::ServiceClaims>(token, &validation)
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

    /// Decode an OIDC access token whose audience is the relying party rather than Keylo's API audience list.
    pub fn decode_oidc_access_token(
        &self,
        token: &str,
        issuer: &str,
    ) -> Result<crate::models::OidcAccessTokenClaims, AuthError> {
        let mut validation = Validation::new(self.algorithm);
        validation.validate_aud = false;
        validation.set_issuer(&[issuer]);
        self.decode_with_key::<crate::models::OidcAccessTokenClaims>(token, &validation)
            .map(|data| data.claims)
            .map_err(|err| match err.kind() {
                ErrorKind::ExpiredSignature => AuthError::ExpiredToken,
                _ => AuthError::InvalidToken,
            })
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

        self.decode_with_key::<crate::models::service::ServiceClaims>(token, &validation)
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
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::rand_core::OsRng;
    use rsa::RsaPrivateKey;

    fn sample_claims(state: &AppState) -> Claims {
        Claims {
            sub: "user:rotation-test".to_string(),
            uid: Some("rotation-user".to_string()),
            principal_id: Some("user-rotation-user".to_string()),
            principal_type: Some("user".to_string()),
            organization_id: None,
            customer_support_grant_id: None,
            iss: state.config.jwt_issuer.clone(),
            aud: "admin-backend".to_string(),
            scope: vec!["read".to_string()],
            role: Vec::new(),
            token_type: "access_token".to_string(),
            exp: chrono::Utc::now().timestamp() + 300,
            iat: chrono::Utc::now().timestamp(),
            jti: "rotation-test-jti".to_string(),
        }
    }

    #[tokio::test]
    async fn claims_extractor_reuses_middleware_claims() {
        let state = {
            let _env_guard = crate::config::test_process_env_lock();
            AppState::default()
        };
        let claims = Claims {
            sub: "user:alice".to_string(),
            uid: Some("user-1".to_string()),
            principal_id: Some("user-user-1".to_string()),
            principal_type: Some("user".to_string()),
            organization_id: None,
            customer_support_grant_id: None,
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

    #[test]
    fn active_passive_rotation_keeps_overlap_and_supports_rollback() {
        let state = AppState::default();
        let keys = state.jwt_keys.clone();
        let old_claims = sample_claims(&state);
        let old_token = keys.sign_token(&old_claims).expect("old token should sign");

        let new_private =
            RsaPrivateKey::new(&mut OsRng, 2048).expect("new RSA key should generate");
        let new_private_pem = new_private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("new private key should encode")
            .to_string();
        let new_public_pem = new_private
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("new public key should encode");

        let old_key_id = keys.active_key_id();
        keys.rotate("rotation-test-next", &new_private_pem, &new_public_pem, 300)
            .expect("rotation should promote a new active key");
        assert_eq!(keys.active_key_id(), "rotation-test-next");
        assert_eq!(keys.passive_key_ids(), vec![old_key_id.clone()]);
        assert_eq!(keys.jwks().keys.len(), 2);
        assert_eq!(keys.decode_token(&old_token).unwrap().sub, old_claims.sub);

        let new_token = keys.sign_token(&old_claims).expect("new token should sign");
        assert_eq!(keys.decode_token(&new_token).unwrap().sub, old_claims.sub);

        keys.rollback(&old_key_id, 300)
            .expect("rollback should use the retained private key");
        assert_eq!(keys.active_key_id(), old_key_id);
        assert_eq!(
            keys.passive_key_ids(),
            vec!["rotation-test-next".to_string()]
        );
        assert_eq!(keys.decode_token(&new_token).unwrap().sub, old_claims.sub);

        assert!(keys.retire_passive("rotation-test-next"));
        assert!(keys.passive_key_ids().is_empty());
        assert!(matches!(
            keys.decode_token(&new_token),
            Err(AuthError::InvalidToken)
        ));
    }

    #[test]
    fn startup_loads_live_passive_key_material_for_verification() {
        let state = AppState::default();
        let (passive_private, passive_public) =
            crate::config::generate_rsa_key_pair().expect("passive key should generate");
        let mut config = state.config.as_ref().clone();
        config.jwt_passive_key_id = Some("startup-passive".to_string());
        config.jwt_passive_private_key_pem = Some(passive_private.clone());
        config.jwt_passive_public_key_pem = Some(passive_public);

        let keys = Keys::from_config(&config).expect("configured passive key should load");
        assert_eq!(keys.passive_key_ids(), vec!["startup-passive"]);
        assert_eq!(keys.jwks().keys.len(), 2);

        let claims = sample_claims(&state);
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("startup-passive".to_string());
        let passive_token = encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(passive_private.as_bytes())
                .expect("passive private key should encode"),
        )
        .expect("passive token should sign");
        keys.decode_token(&passive_token)
            .expect("startup passive key should verify tokens");
    }
}

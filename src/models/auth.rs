use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct KeyloConfiguration {
    pub issuer: String,
    pub jwks_uri: String,
    pub introspection_endpoint: String,
    pub service_token_endpoint: String,
    pub service_introspection_endpoint: String,
    pub user_token_endpoint: String,
    pub admin_token_endpoint: String,
    pub supported_token_types: Vec<String>,
    pub supported_claims: Vec<String>,
    pub supported_signing_algorithms: Vec<String>,
    pub supported_audiences: Vec<String>,
    pub documentation_uri: String,
}

#[derive(Debug, Serialize)]
pub struct AuthBody {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Debug, Deserialize)]
pub struct AuthPayload {
    pub client_id: String,
    pub client_secret: String,
    pub force: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct IntrospectTokenRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct TokenIntrospectResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
}

impl TokenIntrospectResponse {
    pub fn inactive() -> Self {
        Self {
            active: false,
            sub: None,
            principal_id: None,
            principal_type: None,
            scope: None,
            role: None,
            aud: None,
            iss: None,
            exp: None,
            iat: None,
            jti: None,
            token_type: None,
        }
    }

    pub fn from_claims(claims: &crate::models::Claims) -> Self {
        Self {
            active: true,
            sub: Some(claims.sub.clone()),
            principal_id: claims.principal_id.clone(),
            principal_type: claims.principal_type.clone(),
            scope: Some(claims.scope.clone()),
            role: Some(claims.role.clone()),
            aud: Some(claims.aud.clone()),
            iss: Some(claims.iss.clone()),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            jti: Some(claims.jti.clone()),
            token_type: Some(claims.token_type.clone()),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct BlacklistTokenRequest {
    pub token: String,
    pub reason: Option<String>,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CleanupAuditLogsRequest {
    pub retention_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct RotateClientSecretRequest {
    pub new_secret: Option<String>,
    pub revoke_refresh_tokens: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct CreateClientRequest {
    pub client_id: String,
    pub client_secret: String,
    pub name: String,
    pub description: Option<String>,
    pub active: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateClientRequest {
    pub client_secret: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub active: Option<bool>,
}

impl AuthBody {
    pub fn new(access_token: String, refresh_token: Option<String>, expires_in: i64) -> Self {
        Self {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in,
        }
    }
}

#[derive(Serialize)]
pub struct MeResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_type: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub role: Vec<String>,
    pub aud: String,
    pub exp: i64,
    pub iss: String,
    pub jti: String,
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct AuthBody {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Debug, Deserialize)]
pub struct AuthPayload {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct BlacklistTokenRequest {
    pub token: String,
    pub reason: Option<String>,
    pub expires_at: Option<i64>,
}

impl AuthBody {
    pub fn new(access_token: String, refresh_token: String, expires_in: i64) -> Self {
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
    pub aud: String,
    pub exp: i64,
    pub iss: String,
    pub jti: String,
}
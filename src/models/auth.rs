use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct AuthBody {
    pub access_token: String,
    pub token_type: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthPayload {
    pub client_id: String,
    pub client_secret: String,
}

impl AuthBody {
    pub fn new(access_token: String) -> Self {
        Self {
            access_token,
            token_type: "Bearer".to_string(),
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
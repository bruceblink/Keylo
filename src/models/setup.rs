use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct SetupCheck {
    pub key: String,
    pub label: String,
    pub ok: bool,
    pub required: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct SetupEndpoints {
    pub issuer: String,
    pub jwks_uri: String,
    pub discovery_uri: String,
    pub admin_token_endpoint: String,
    pub user_token_endpoint: String,
    pub service_token_endpoint: String,
}

#[derive(Debug, Serialize)]
pub struct SetupStatusResponse {
    pub enabled: bool,
    pub completed: bool,
    pub environment: String,
    pub checks: Vec<SetupCheck>,
    pub endpoints: SetupEndpoints,
}

#[derive(Debug, Deserialize)]
pub struct SetupInitializeRequest {
    pub admin_client_id: Option<String>,
    pub admin_client_secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SetupInitializeResponse {
    pub completed: bool,
    pub admin_client_id: String,
    pub endpoints: SetupEndpoints,
}

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IdentitySource {
    pub id: String,
    pub name: String,
    pub source_type: String,
    pub display_name: String,
    pub description: Option<String>,
    pub config: Value,
    pub claim_mapping: Value,
    pub jit_enabled: bool,
    pub auto_link_enabled: bool,
    pub active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateIdentitySourceRequest {
    pub name: String,
    pub source_type: String,
    pub display_name: String,
    pub description: Option<String>,
    pub config: Option<Value>,
    pub claim_mapping: Option<Value>,
    pub jit_enabled: Option<bool>,
    pub auto_link_enabled: Option<bool>,
    pub active: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateIdentitySourceRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub config: Option<Value>,
    pub claim_mapping: Option<Value>,
    pub jit_enabled: Option<bool>,
    pub auto_link_enabled: Option<bool>,
    pub active: Option<bool>,
}

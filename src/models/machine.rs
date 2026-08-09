use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

pub const MACHINE_SCOPE_PLATFORM: &str = "platform";
pub const MACHINE_SCOPE_ORGANIZATION: &str = "organization";
pub const MACHINE_CREDENTIAL_STATUS_ACTIVE: &str = "active";
pub const MACHINE_CREDENTIAL_STATUS_REVOKED: &str = "revoked";
pub const MACHINE_AUTHORIZATION_SCOPE: &str = "authorization";
pub const MACHINE_AUTHORIZATION_AUDIENCE: &str = "admin-backend";

/// Stable device Principal metadata and its immutable authorization boundary.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct DeviceInfo {
    pub principal_id: String,
    pub device_id: String,
    pub display_name: String,
    pub active: bool,
    pub scope_kind: String,
    pub organization_id: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// Safe MachineCredential metadata; the hash and raw API key never leave the server.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct MachineCredentialInfo {
    pub key_id: String,
    pub prefix: String,
    pub principal_id: String,
    pub organization_id: Option<String>,
    pub status: String,
    pub expires_at: Option<NaiveDateTime>,
    pub last_used_at: Option<NaiveDateTime>,
    pub created_by_principal_id: Option<String>,
    pub allowed_scopes: Vec<String>,
    pub allowed_audiences: Vec<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// One-time create or rotation response for a raw machine API key.
#[derive(Debug, Serialize)]
pub struct MachineCredentialSecretResponse {
    #[serde(flatten)]
    pub credential: MachineCredentialInfo,
    pub api_key: String,
}

/// External input for an administrator to create a stable machine device.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDeviceRequest {
    pub device_id: String,
    pub display_name: String,
    /// Platform routes may set this explicitly; organization routes derive it
    /// from the path and reject this caller-provided field.
    pub organization_id: Option<String>,
}

/// Only presentation and enabled state are mutable after device creation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateDeviceRequest {
    pub display_name: Option<String>,
    pub active: Option<bool>,
}

/// API-key capabilities are independent of RBAC and only constrain it further.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateMachineCredentialRequest {
    pub expires_at: Option<String>,
    pub allowed_scopes: Vec<String>,
    pub allowed_audiences: Vec<String>,
    /// Platform routes may set this explicitly; organization routes derive it
    /// from the path and reject this caller-provided field.
    pub organization_id: Option<String>,
}

/// Replaces a key's secret while preserving its Principal and immutable scope.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateMachineCredentialRequest {
    pub expires_at: Option<String>,
    pub allowed_scopes: Option<Vec<String>>,
    pub allowed_audiences: Option<Vec<String>>,
}

/// Optional reason makes revocation auditable without exposing a raw secret.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeMachineCredentialRequest {
    pub reason: Option<String>,
}

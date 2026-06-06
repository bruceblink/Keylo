use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Principal {
    pub id: String,
    pub principal_type: String,
    pub subject: String,
    pub ref_id: String,
    pub display_name: String,
    pub active: bool,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Debug, Deserialize)]
pub struct PrincipalListQuery {
    pub principal_type: Option<String>,
    pub active: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct PrincipalEffectivePermissionsResponse {
    pub principal: Principal,
    pub roles: Vec<crate::models::Role>,
    pub permissions: Vec<crate::models::Permission>,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeCheckRequest {
    pub permission: Option<String>,
    pub app: Option<String>,
    pub resource_type: Option<String>,
    pub resource_code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeBatchCheckRequest {
    pub checks: Vec<AuthorizeCheckRequest>,
}

#[derive(Debug, Serialize)]
pub struct AuthorizeCheckResponse {
    pub allowed: bool,
    pub principal_id: String,
    pub matched_permission: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthorizeBatchCheckResponse {
    pub results: Vec<AuthorizeCheckResponse>,
}

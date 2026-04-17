use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;

/// 用户模型
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub active: bool,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

/// 创建用户请求
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: Option<String>,
}

/// 创建用户并绑定角色模板（原子）
#[derive(Debug, Deserialize)]
pub struct ProvisionUserRequest {
    pub username: String,
    pub email: String,
    pub password: Option<String>,
    #[serde(default)]
    pub role_ids: Vec<String>,
    #[serde(default)]
    pub role_names: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProvisionUserResponse {
    pub user: User,
    pub roles: Vec<crate::models::Role>,
    pub permissions: Vec<crate::models::Permission>,
}

/// 更新用户请求
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub active: Option<bool>,
}

/// 重置密码请求
#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub password: String,
}

/// 更改密码请求
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// 第三方系统用户导入项
#[derive(Debug, Deserialize)]
pub struct ThirdPartyUserImportItem {
    pub external_user_id: String,
    pub username: String,
    pub email: String,
    pub password: Option<String>,
    pub active: Option<bool>,
    pub roles: Option<Vec<String>>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// 第三方系统用户批量导入请求
#[derive(Debug, Deserialize)]
pub struct ThirdPartyUserImportRequest {
    /// 第三方系统标识（例如 agileboot、erp、crm）
    pub provider: String,
    pub users: Vec<ThirdPartyUserImportItem>,
    pub dry_run: Option<bool>,
}

/// 第三方系统用户导入结果项
#[derive(Debug, Clone, Serialize)]
pub struct ThirdPartyUserImportResultItem {
    pub external_user_id: String,
    pub user_id: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<MigrationErrorCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// 迁移失败原因统一错误码
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MigrationErrorCode {
    #[serde(rename = "migration_invalid_input")]
    InvalidInput,
    #[serde(rename = "migration_conflict")]
    Conflict,
    #[serde(rename = "migration_mapping_error")]
    MappingError,
    #[serde(rename = "migration_role_assignment_failed")]
    RoleAssignmentFailed,
    #[serde(rename = "migration_internal_error")]
    InternalError,
    #[serde(rename = "migration_provider_invalid")]
    ProviderInvalid,
    #[serde(rename = "migration_not_found")]
    NotFound,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThirdPartyUserImportSummary {
    pub total: usize,
    pub created: usize,
    pub updated: usize,
    pub linked: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThirdPartyUserImportOutput {
    pub provider: String,
    pub dry_run: bool,
    pub summary: ThirdPartyUserImportSummary,
    pub results: Vec<ThirdPartyUserImportResultItem>,
}

/// 单用户 JIT 迁移注册请求（登录时迁移）
#[derive(Debug, Deserialize)]
pub struct ThirdPartyJitRegisterRequest {
    pub provider: String,
    pub external_user_id: String,
    pub username: String,
    pub email: String,
    pub password: Option<String>,
    pub active: Option<bool>,
    pub roles: Option<Vec<String>>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize)]
pub struct ThirdPartyJitRegisterResponse {
    pub success: bool,
    pub provider: String,
    pub migration_status: String,
    pub user_id: String,
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationJobStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct MigrationBatchJob {
    pub job_id: String,
    pub provider: String,
    pub dry_run: bool,
    pub total_users: usize,
    pub actor: String,
    pub status: MigrationJobStatus,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<MigrationErrorCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ThirdPartyUserImportOutput>,
}

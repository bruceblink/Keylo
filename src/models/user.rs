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
#[derive(Debug, Serialize)]
pub struct ThirdPartyUserImportResultItem {
    pub external_user_id: String,
    pub user_id: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

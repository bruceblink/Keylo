use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// 角色模型
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// 创建角色的请求
#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
}

/// 更新角色的请求
#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

/// 权限模型
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Permission {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// 创建权限的请求
#[derive(Debug, Deserialize)]
pub struct CreatePermissionRequest {
    pub name: String,
    pub description: Option<String>,
}

/// 更新权限的请求
#[derive(Debug, Deserialize)]
pub struct UpdatePermissionRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

/// 用户角色关系
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserRole {
    pub user_id: String,
    pub role_id: String,
    pub assigned_at: chrono::DateTime<chrono::Utc>,
}

/// 角色权限关系
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RolePermission {
    pub role_id: String,
    pub permission_id: String,
    pub assigned_at: chrono::DateTime<chrono::Utc>,
}

/// 分配角色的请求
#[derive(Debug, Deserialize)]
pub struct AssignRoleRequest {
    pub role_id: String,
}

/// 分配权限的请求
#[derive(Debug, Deserialize)]
pub struct AssignPermissionRequest {
    pub permission_id: String,
}
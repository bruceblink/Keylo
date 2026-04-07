use anyhow::Result;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::models::*;

/// 角色相关数据库操作
/// 创建角色
pub async fn create_role(pool: &PgPool, name: &str, description: Option<&str>) -> Result<Role> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Local::now().naive_utc();

    let role = sqlx::query_as::<_, Role>(
        r#"
        INSERT INTO roles (id, name, description, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, name, description, created_at, updated_at
        "#,
    )
    .bind(&id)
    .bind(name)
    .bind(description)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(role)
}

/// 获取所有角色
pub async fn get_all_roles(pool: &PgPool) -> Result<Vec<Role>> {
    let roles = sqlx::query_as::<_, Role>(
        "SELECT id, name, description, created_at, updated_at FROM roles ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    Ok(roles)
}

/// 根据ID获取角色
pub async fn get_role_by_id(pool: &PgPool, role_id: &str) -> Result<Option<Role>> {
    let role = sqlx::query_as::<_, Role>(
        "SELECT id, name, description, created_at, updated_at FROM roles WHERE id = $1",
    )
    .bind(role_id)
    .fetch_optional(pool)
    .await?;

    Ok(role)
}

/// 根据名称获取角色
pub async fn get_role_by_name(pool: &PgPool, name: &str) -> Result<Option<Role>> {
    let role = sqlx::query_as::<_, Role>(
        "SELECT id, name, description, created_at, updated_at FROM roles WHERE name = $1",
    )
    .bind(name)
    .fetch_optional(pool)
    .await?;

    Ok(role)
}

/// 更新角色
pub async fn update_role(
    pool: &PgPool,
    role_id: &str,
    name: Option<&str>,
    description: Option<&str>,
) -> Result<Option<Role>> {
    let now = chrono::Local::now().naive_utc();

    let role = sqlx::query_as::<_, Role>(
        r#"
        UPDATE roles
        SET name = COALESCE($2, name),
            description = COALESCE($3, description),
            updated_at = $4
        WHERE id = $1
        RETURNING id, name, description, created_at, updated_at
        "#,
    )
    .bind(role_id)
    .bind(name)
    .bind(description)
    .bind(now)
    .fetch_optional(pool)
    .await?;

    Ok(role)
}

/// 删除角色
pub async fn delete_role(pool: &PgPool, role_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM roles WHERE id = $1")
        .bind(role_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// 权限相关数据库操作
/// 创建权限
pub async fn create_permission(
    pool: &PgPool,
    name: &str,
    description: Option<&str>,
) -> Result<Permission> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Local::now().naive_utc();

    let permission = sqlx::query_as::<_, Permission>(
        r#"
        INSERT INTO permissions (id, name, description, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, name, description, created_at, updated_at
        "#,
    )
    .bind(&id)
    .bind(name)
    .bind(description)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(permission)
}

/// 获取所有权限
pub async fn get_all_permissions(pool: &PgPool) -> Result<Vec<Permission>> {
    let permissions = sqlx::query_as::<_, Permission>(
        "SELECT id, name, description, created_at, updated_at FROM permissions ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    Ok(permissions)
}

/// 根据ID获取权限
pub async fn get_permission_by_id(
    pool: &PgPool,
    permission_id: &str,
) -> Result<Option<Permission>> {
    let permission = sqlx::query_as::<_, Permission>(
        "SELECT id, name, description, created_at, updated_at FROM permissions WHERE id = $1",
    )
    .bind(permission_id)
    .fetch_optional(pool)
    .await?;

    Ok(permission)
}

/// 根据名称获取权限
pub async fn get_permission_by_name(pool: &PgPool, name: &str) -> Result<Option<Permission>> {
    let permission = sqlx::query_as::<_, Permission>(
        "SELECT id, name, description, created_at, updated_at FROM permissions WHERE name = $1",
    )
    .bind(name)
    .fetch_optional(pool)
    .await?;

    Ok(permission)
}

/// 更新权限
pub async fn update_permission(
    pool: &PgPool,
    permission_id: &str,
    name: Option<&str>,
    description: Option<&str>,
) -> Result<Option<Permission>> {
    let now = chrono::Local::now().naive_utc();

    let permission = sqlx::query_as::<_, Permission>(
        r#"
        UPDATE permissions
        SET name = COALESCE($2, name),
            description = COALESCE($3, description),
            updated_at = $4
        WHERE id = $1
        RETURNING id, name, description, created_at, updated_at
        "#,
    )
    .bind(permission_id)
    .bind(name)
    .bind(description)
    .bind(now)
    .fetch_optional(pool)
    .await?;

    Ok(permission)
}

/// 删除权限
pub async fn delete_permission(pool: &PgPool, permission_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM permissions WHERE id = $1")
        .bind(permission_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// 用户角色关系操作
/// 为用户分配角色
pub async fn assign_role_to_user(pool: &PgPool, user_id: &str, role_id: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(user_id)
    .bind(role_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// 撤销用户的角色
pub async fn revoke_role_from_user(pool: &PgPool, user_id: &str, role_id: &str) -> Result<bool> {
    let result =
        sqlx::query("DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2")
            .bind(user_id)
            .bind(role_id)
            .execute(pool)
            .await?;

    Ok(result.rows_affected() > 0)
}

/// 获取用户的所有角色
pub async fn get_user_roles(pool: &PgPool, user_id: &str) -> Result<Vec<Role>> {
    let roles = sqlx::query_as::<_, Role>(
        r#"
        SELECT r.id, r.name, r.description, r.created_at, r.updated_at
        FROM roles r
        INNER JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = $1
        ORDER BY r.name
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(roles)
}

/// 获取角色的所有用户
pub async fn get_role_users(pool: &PgPool, role_id: &str) -> Result<Vec<String>> {
    let rows = sqlx::query("SELECT user_id FROM user_roles WHERE role_id = $1")
        .bind(role_id)
        .fetch_all(pool)
        .await?;

    Ok(rows.into_iter().map(|r| r.get("user_id")).collect())
}

/// 检查用户是否有特定角色
pub async fn user_has_role(pool: &PgPool, user_id: &str, role_name: &str) -> Result<bool> {
    let row = sqlx::query(
        r#"
        SELECT COUNT(*) as count
        FROM user_roles ur
        INNER JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = $1 AND r.name = $2
        "#,
    )
    .bind(user_id)
    .bind(role_name)
    .fetch_one(pool)
    .await?;

    let count: i64 = row.get::<Option<i64>, _>("count").unwrap_or(0);
    Ok(count > 0)
}

/// 角色权限关系操作
/// 为角色分配权限
pub async fn assign_permission_to_role(
    pool: &PgPool,
    role_id: &str,
    permission_id: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(role_id)
    .bind(permission_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// 撤销角色的权限
pub async fn revoke_permission_from_role(
    pool: &PgPool,
    role_id: &str,
    permission_id: &str,
) -> Result<bool> {
    let result =
        sqlx::query("DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2")
            .bind(role_id)
            .bind(permission_id)
            .execute(pool)
            .await?;

    Ok(result.rows_affected() > 0)
}

/// 获取角色的所有权限
pub async fn get_role_permissions(pool: &PgPool, role_id: &str) -> Result<Vec<Permission>> {
    let permissions = sqlx::query_as::<_, Permission>(
        r#"
        SELECT p.id, p.name, p.description, p.created_at, p.updated_at
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = $1
        ORDER BY p.name
        "#,
    )
    .bind(role_id)
    .fetch_all(pool)
    .await?;

    Ok(permissions)
}

/// 获取权限的所有角色
pub async fn get_permission_roles(pool: &PgPool, permission_id: &str) -> Result<Vec<String>> {
    let rows =
        sqlx::query("SELECT role_id FROM role_permissions WHERE permission_id = $1")
            .bind(permission_id)
            .fetch_all(pool)
            .await?;

    Ok(rows.into_iter().map(|r| r.get("role_id")).collect())
}

/// 检查用户是否有特定权限
pub async fn user_has_permission(
    pool: &PgPool,
    user_id: &str,
    permission_name: &str,
) -> Result<bool> {
    let row = sqlx::query(
        r#"
        SELECT COUNT(*) as count
        FROM user_roles ur
        INNER JOIN role_permissions rp ON ur.role_id = rp.role_id
        INNER JOIN permissions p ON rp.permission_id = p.id
        WHERE ur.user_id = $1 AND p.name = $2
        "#,
    )
    .bind(user_id)
    .bind(permission_name)
    .fetch_one(pool)
    .await?;

    let count: i64 = row.get::<Option<i64>, _>("count").unwrap_or(0);
    Ok(count > 0)
}

/// 获取用户的所有权限（通过角色）
pub async fn get_user_permissions(pool: &PgPool, user_id: &str) -> Result<Vec<Permission>> {
    let permissions = sqlx::query_as::<_, Permission>(
        r#"
        SELECT DISTINCT p.id, p.name, p.description, p.created_at, p.updated_at
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        INNER JOIN user_roles ur ON rp.role_id = ur.role_id
        WHERE ur.user_id = $1
        ORDER BY p.name
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(permissions)
}


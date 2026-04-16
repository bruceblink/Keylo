use anyhow::Result;
use bcrypt::{hash, verify, DEFAULT_COST};
use serde_json::Value;
use sqlx::PgPool;
use sqlx::Row;
use uuid::Uuid;

use crate::models::User;

const PASSWORD_COST: u32 = DEFAULT_COST;

fn hash_password(password: &str) -> Result<String> {
    Ok(hash(password, PASSWORD_COST)?)
}

fn verify_password_hash(password: &str, password_hash: &str) -> Result<bool> {
    Ok(verify(password, password_hash)?)
}

/// 获取用户
pub async fn get_user_by_id(pool: &PgPool, user_id: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, password_hash, active, created_at, updated_at FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// 根据用户名获取用户
pub async fn get_user_by_username(pool: &PgPool, username: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, password_hash, active, created_at, updated_at FROM users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// 根据邮箱获取用户
pub async fn get_user_by_email(pool: &PgPool, email: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, password_hash, active, created_at, updated_at FROM users WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// 列出用户，支持分页
pub async fn list_users(pool: &PgPool, limit: i64, offset: i64) -> Result<Vec<User>> {
    let users = sqlx::query_as::<_, User>(
        "SELECT id, username, email, password_hash, active, created_at, updated_at FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(users)
}

/// 创建用户
pub async fn create_user(
    pool: &PgPool,
    username: &str,
    email: &str,
    password: Option<&str>,
) -> Result<User> {
    let id = Uuid::new_v4().to_string();
    let password_hash = if let Some(p) = password {
        Some(hash_password(p)?)
    } else {
        None
    };
    let now = chrono::Local::now().naive_utc();

    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (id, username, email, password_hash, active, created_at, updated_at)
        VALUES ($1, $2, $3, $4, TRUE, $5, $6)
        RETURNING id, username, email, password_hash, active, created_at, updated_at
        "#,
    )
    .bind(id)
    .bind(username)
    .bind(email)
    .bind(password_hash)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

/// 更新用户
pub async fn update_user(
    pool: &PgPool,
    user_id: &str,
    username: Option<&str>,
    email: Option<&str>,
    password: Option<&str>,
    active: Option<bool>,
) -> Result<Option<User>> {
    let password_hash = if let Some(p) = password {
        Some(hash_password(p)?)
    } else {
        None
    };
    let now = chrono::Local::now().naive_utc();

    let user = sqlx::query_as::<_, User>(
        r#"
        UPDATE users
        SET username = COALESCE($2, username),
            email = COALESCE($3, email),
            password_hash = COALESCE($4, password_hash),
            active = COALESCE($5, active),
            updated_at = $6
        WHERE id = $1
        RETURNING id, username, email, password_hash, active, created_at, updated_at
        "#,
    )
    .bind(user_id)
    .bind(username)
    .bind(email)
    .bind(password_hash)
    .bind(active)
    .bind(now)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// 更新用户激活状态
pub async fn set_user_active(pool: &PgPool, user_id: &str, active: bool) -> Result<bool> {
    let result = sqlx::query("UPDATE users SET active = $2, updated_at = $3 WHERE id = $1")
        .bind(user_id)
        .bind(active)
        .bind(chrono::Local::now().naive_utc())
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// 删除用户
pub async fn delete_user(pool: &PgPool, user_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// 验证用户凭证
pub async fn validate_user_credentials(
    pool: &PgPool,
    username: &str,
    password: &str,
) -> Result<Option<User>> {
    if let Some(user) = get_user_by_username(pool, username).await? {
        if !user.active {
            return Ok(None);
        }

        if let Some(password_hash) = user.password_hash.as_deref() {
            if verify_password_hash(password, password_hash)? {
                return Ok(Some(user));
            }
        }
    }

    Ok(None)
}

/// 重置用户密码
pub async fn reset_user_password(pool: &PgPool, user_id: &str, password: &str) -> Result<bool> {
    let password_hash = hash_password(password)?;

    let result = sqlx::query("UPDATE users SET password_hash = $2, updated_at = $3 WHERE id = $1")
        .bind(user_id)
        .bind(password_hash)
        .bind(chrono::Local::now().naive_utc())
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// 用户更改密码（需要验证当前密码）
pub async fn change_user_password(
    pool: &PgPool,
    user_id: &str,
    current_password: &str,
    new_password: &str,
) -> Result<bool> {
    // 首先验证当前密码
    if let Some(user) = get_user_by_id(pool, user_id).await? {
        if !user.active {
            return Ok(false);
        }

        if let Some(password_hash) = user.password_hash.as_deref() {
            if !verify_password_hash(current_password, password_hash)? {
                return Ok(false); // 当前密码不正确
            }
        } else {
            return Ok(false); // 用户没有密码
        }
    } else {
        return Ok(false); // 用户不存在
    }

    // 验证通过，更新密码
    let new_password_hash = hash_password(new_password)?;

    let result = sqlx::query("UPDATE users SET password_hash = $2, updated_at = $3 WHERE id = $1")
        .bind(user_id)
        .bind(new_password_hash)
        .bind(chrono::Local::now().naive_utc())
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// 根据外部系统映射查询用户ID
pub async fn get_mapped_user_id(
    pool: &PgPool,
    provider: &str,
    external_user_id: &str,
) -> Result<Option<String>> {
    let row = sqlx::query(
        "SELECT user_id FROM external_user_mappings WHERE provider = $1 AND external_user_id = $2",
    )
    .bind(provider)
    .bind(external_user_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|value| value.get("user_id")))
}

/// 创建或更新外部系统用户映射
pub async fn upsert_external_user_mapping(
    pool: &PgPool,
    provider: &str,
    external_user_id: &str,
    user_id: &str,
    metadata: Option<&Value>,
) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Local::now().naive_utc();

    sqlx::query(
        r#"
        INSERT INTO external_user_mappings
            (id, provider, external_user_id, user_id, metadata, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $6)
        ON CONFLICT (provider, external_user_id) DO UPDATE
            SET user_id = EXCLUDED.user_id,
                metadata = EXCLUDED.metadata,
                updated_at = EXCLUDED.updated_at
        "#,
    )
    .bind(id)
    .bind(provider)
    .bind(external_user_id)
    .bind(user_id)
    .bind(metadata)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// 获取用户总量
pub async fn count_users(pool: &PgPool) -> Result<i64> {
    let row = sqlx::query("SELECT COUNT(*) AS count FROM users")
        .fetch_one(pool)
        .await?;

    Ok(row.get::<Option<i64>, _>("count").unwrap_or(0))
}

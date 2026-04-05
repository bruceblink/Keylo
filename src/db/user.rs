use anyhow::Result;
use bcrypt::{hash, verify, DEFAULT_COST};
use sqlx::PgPool;
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
    let user = sqlx::query_as!(
        User,
        "SELECT id, username, email, password_hash, active, created_at, updated_at FROM users WHERE id = $1",
        user_id
    )
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// 根据用户名获取用户
pub async fn get_user_by_username(pool: &PgPool, username: &str) -> Result<Option<User>> {
    let user = sqlx::query_as!(
        User,
        "SELECT id, username, email, password_hash, active, created_at, updated_at FROM users WHERE username = $1",
        username
    )
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// 列出用户，支持分页
pub async fn list_users(pool: &PgPool, limit: i64, offset: i64) -> Result<Vec<User>> {
    let users = sqlx::query_as!(
        User,
        "SELECT id, username, email, password_hash, active, created_at, updated_at FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        limit,
        offset
    )
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

    let user = sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (id, username, email, password_hash, active, created_at, updated_at)
        VALUES ($1, $2, $3, $4, TRUE, $5, $6)
        RETURNING id, username, email, password_hash, active, created_at, updated_at
        "#,
        id,
        username,
        email,
        password_hash,
        now,
        now
    )
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

    let user = sqlx::query_as!(
        User,
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
        user_id,
        username,
        email,
        password_hash,
        active,
        now
    )
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// 删除用户
pub async fn delete_user(pool: &PgPool, user_id: &str) -> Result<bool> {
    let result: sqlx::postgres::PgQueryResult = sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
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

    let result: sqlx::postgres::PgQueryResult = sqlx::query!(
        "UPDATE users SET password_hash = $2, updated_at = $3 WHERE id = $1",
        user_id,
        password_hash,
        chrono::Local::now().naive_utc()
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

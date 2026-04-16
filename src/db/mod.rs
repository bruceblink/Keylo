use crate::config::Config;
use crate::utils::validate_password_complexity;
use anyhow::Result;
use bcrypt::{hash, DEFAULT_COST};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;
use uuid::Uuid;

pub mod oauth;
pub mod rbac;
pub mod service;
pub mod user;

pub use oauth::*;
pub use rbac::*;
pub use service::*;
pub use user::*;

/// 初始化数据库连接池
pub async fn init_db_pool(database_url: &str) -> Result<PgPool> {
    let max_connections: u32 = std::env::var("DB_POOL_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);

    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(database_url)
        .await?;

    Ok(pool)
}

/// 运行数据库迁移
pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

/// 创建客户端
pub async fn create_client(
    pool: &PgPool,
    client_id: &str,
    client_secret: &str,
    name: &str,
    description: Option<&str>,
) -> Result<()> {
    let hashed = hash(client_secret, DEFAULT_COST)?;
    sqlx::query("INSERT INTO clients (id, secret, name, description) VALUES ($1, $2, $3, $4)")
        .bind(client_id)
        .bind(&hashed)
        .bind(name)
        .bind(description)
        .execute(pool)
        .await?;

    Ok(())
}

/// 创建或更新客户端
pub async fn upsert_client(
    pool: &PgPool,
    client_id: &str,
    client_secret: &str,
    name: &str,
    description: Option<&str>,
) -> Result<()> {
    let hashed = hash(client_secret, DEFAULT_COST)?;
    sqlx::query(
        "INSERT INTO clients (id, secret, name, description, active)
         VALUES ($1, $2, $3, $4, TRUE)
         ON CONFLICT (id) DO UPDATE
         SET secret = EXCLUDED.secret,
             name = EXCLUDED.name,
             description = EXCLUDED.description,
             active = TRUE,
             updated_at = NOW()",
    )
    .bind(client_id)
    .bind(&hashed)
    .bind(name)
    .bind(description)
    .execute(pool)
    .await?;

    Ok(())
}

/// 初始化默认客户端
pub async fn seed_default_clients(pool: &PgPool) -> Result<()> {
    upsert_client(
        pool,
        "web",
        "web-secret",
        "Web Client",
        Some("Default web client"),
    )
    .await?;

    let admin_client_id = std::env::var("ADMIN_CLIENT_ID").ok();
    let admin_client_secret = std::env::var("ADMIN_CLIENT_SECRET").ok();

    if let (Some(id), Some(secret)) = (admin_client_id, admin_client_secret) {
        // Use INSERT ... ON CONFLICT DO NOTHING so that a rotated secret is never
        // overwritten by a subsequent application restart or test setup call.
        let hashed_admin_secret = hash(&secret, DEFAULT_COST)?;
        sqlx::query(
            "INSERT INTO clients (id, secret, name, description, active)
             VALUES ($1, $2, 'Admin Client', 'Configured admin client', TRUE)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&id)
        .bind(&hashed_admin_secret)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// 初始化超级管理员用户（可选）
pub async fn seed_super_admin_user(pool: &PgPool, config: &Config) -> Result<()> {
    if !config.enable_super_admin_bootstrap {
        return Ok(());
    }

    let username = config
        .super_admin_username
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("SUPER_ADMIN_USERNAME is required when bootstrap is enabled")
        })?;
    let email = config
        .super_admin_email
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("SUPER_ADMIN_EMAIL is required when bootstrap is enabled")
        })?;
    let password = config
        .super_admin_password
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("SUPER_ADMIN_PASSWORD is required when bootstrap is enabled")
        })?;

    if let Err(msg) = validate_password_complexity(password) {
        anyhow::bail!("SUPER_ADMIN_PASSWORD is insecure: {}", msg);
    }

    let super_role = match get_role_by_name(pool, "super_admin").await? {
        Some(role) => role,
        None => create_role(pool, "super_admin", Some("System super administrator")).await?,
    };

    let user = if let Some(existing) = get_user_by_username(pool, username).await? {
        update_user(
            pool,
            &existing.id,
            Some(username),
            Some(email),
            Some(password),
            Some(true),
        )
        .await?
        .unwrap_or(existing)
    } else if let Some(existing_email) = get_user_by_email(pool, email).await? {
        update_user(
            pool,
            &existing_email.id,
            Some(username),
            Some(email),
            Some(password),
            Some(true),
        )
        .await?
        .unwrap_or(existing_email)
    } else {
        create_user(pool, username, email, Some(password)).await?
    };

    assign_role_to_user(pool, &user.id, &super_role.id).await?;
    if get_permission_by_name(pool, "admin.full").await?.is_none() {
        let permission =
            create_permission(pool, "admin.full", Some("Full admin permission")).await?;
        let _ = assign_permission_to_role(pool, &super_role.id, &permission.id).await;
    }

    create_audit_log(
        pool,
        "bootstrap.super_admin",
        Some("system"),
        Some(&format!("username={}, user_id={}", username, user.id)),
    )
    .await?;

    Ok(())
}

/// 获取所有活跃客户端
pub async fn get_all_active_clients(pool: &PgPool) -> Result<Vec<(String, String)>> {
    let rows = sqlx::query("SELECT id, secret FROM clients WHERE active = TRUE")
        .fetch_all(pool)
        .await?;

    Ok(rows
        .into_iter()
        .map(|row| (row.get("id"), row.get("secret")))
        .collect())
}

/// 获取客户端密钥
/// 获取客户端凭证信息
pub async fn get_client_auth_info(
    pool: &PgPool,
    client_id: &str,
) -> Result<Option<(String, bool)>> {
    let row = sqlx::query("SELECT secret FROM clients WHERE id = $1 AND active = TRUE")
        .bind(client_id)
        .fetch_optional(pool)
        .await?;

    let configured_admin_id = std::env::var("ADMIN_CLIENT_ID").ok();
    Ok(row.map(|r| {
        let is_admin = configured_admin_id
            .as_deref()
            .is_some_and(|admin_id| admin_id == client_id);
        (r.get("secret"), is_admin)
    }))
}

/// 轮换客户端密钥
pub async fn rotate_client_secret(
    pool: &PgPool,
    client_id: &str,
    new_secret: &str,
) -> Result<bool> {
    let hashed = hash(new_secret, DEFAULT_COST)?;
    let result = sqlx::query(
        "UPDATE clients
         SET secret = $2, updated_at = NOW()
         WHERE id = $1 AND active = TRUE",
    )
    .bind(client_id)
    .bind(&hashed)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// 列出所有客户端（管理后台）
pub async fn list_clients_for_admin(
    pool: &PgPool,
) -> Result<Vec<(String, String, Option<String>, bool, i64)>> {
    let rows = sqlx::query(
        "SELECT id, name, description, active,
                extract(epoch from updated_at)::bigint as updated_at
         FROM clients
         ORDER BY updated_at DESC",
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            (
                row.get("id"),
                row.get("name"),
                row.get("description"),
                row.get("active"),
                row.get("updated_at"),
            )
        })
        .collect())
}

/// 创建管理客户端
pub async fn create_management_client(
    pool: &PgPool,
    client_id: &str,
    client_secret: &str,
    name: &str,
    description: Option<&str>,
    active: bool,
) -> Result<()> {
    let hashed = hash(client_secret, DEFAULT_COST)?;
    sqlx::query(
        "INSERT INTO clients (id, secret, name, description, active)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(client_id)
    .bind(&hashed)
    .bind(name)
    .bind(description)
    .bind(active)
    .execute(pool)
    .await?;

    Ok(())
}

/// 更新管理客户端
pub async fn update_management_client(
    pool: &PgPool,
    client_id: &str,
    client_secret: Option<&str>,
    name: Option<&str>,
    description: Option<&str>,
    active: Option<bool>,
) -> Result<bool> {
    let hashed_secret: Option<String> = client_secret.map(|s| hash(s, DEFAULT_COST)).transpose()?;
    let result = sqlx::query(
        "UPDATE clients
         SET secret = COALESCE($2, secret),
             name = COALESCE($3, name),
             description = COALESCE($4, description),
             active = COALESCE($5, active),
             updated_at = NOW()
         WHERE id = $1",
    )
    .bind(client_id)
    .bind(hashed_secret.as_deref())
    .bind(name)
    .bind(description)
    .bind(active)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// 创建会话记录
pub async fn create_session(
    pool: &PgPool,
    session_id: &str,
    user_id: &str,
    token: &str,
    expires_at: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token, expires_at) VALUES ($1, $2, $3, to_timestamp($4))"
    )
    .bind(session_id)
    .bind(user_id)
    .bind(token)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// 撤销会话
pub async fn revoke_session(pool: &PgPool, session_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(session_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// 获取用户会话
pub async fn get_user_sessions(pool: &PgPool, user_id: &str) -> Result<Vec<(String, String)>> {
    let rows =
        sqlx::query("SELECT id, token FROM sessions WHERE user_id = $1 AND expires_at > NOW()")
            .bind(user_id)
            .fetch_all(pool)
            .await?;

    Ok(rows
        .into_iter()
        .map(|row| (row.get("id"), row.get("token")))
        .collect())
}

/// 创建 Refresh Token
pub async fn create_refresh_token(
    pool: &PgPool,
    token_id: &str,
    client_id: &str,
    token: &str,
    expires_at: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO refresh_tokens (id, client_id, token, expires_at) VALUES ($1, $2, $3, to_timestamp($4))"
    )
    .bind(token_id)
    .bind(client_id)
    .bind(token)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// 验证 Refresh Token
pub async fn validate_refresh_token(
    pool: &PgPool,
    token: &str,
) -> Result<Option<(String, String)>> {
    let row = sqlx::query(
        "SELECT id, client_id FROM refresh_tokens 
         WHERE token = $1 AND expires_at > NOW() AND revoked = FALSE",
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| (r.get("id"), r.get("client_id"))))
}

/// 撤销 Refresh Token
pub async fn revoke_refresh_token(pool: &PgPool, token_id: &str) -> Result<()> {
    sqlx::query("UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW() WHERE id = $1")
        .bind(token_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// 撤销客户端的所有 Refresh Token
pub async fn revoke_client_refresh_tokens(pool: &PgPool, client_id: &str) -> Result<()> {
    sqlx::query(
        "UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW() WHERE client_id = $1",
    )
    .bind(client_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// 清理过期的 Refresh Token
pub async fn cleanup_expired_refresh_tokens(pool: &PgPool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM refresh_tokens WHERE expires_at <= NOW()")
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

/// 将 Token 加入黑名单
pub async fn blacklist_token(
    pool: &PgPool,
    token: &str,
    reason: Option<&str>,
    expires_at: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO blacklisted_tokens (id, token, reason, expires_at) 
         VALUES ($1, $2, $3, to_timestamp($4))
         ON CONFLICT (token) DO NOTHING",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(token)
    .bind(reason)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// 检查 Token 是否在黑名单中
pub async fn is_token_blacklisted(pool: &PgPool, token: &str) -> Result<bool> {
    let row = sqlx::query(
        "SELECT 1 FROM blacklisted_tokens 
         WHERE token = $1 AND expires_at > NOW() LIMIT 1",
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;

    Ok(row.is_some())
}

/// 清理过期的黑名单 Token
pub async fn cleanup_expired_blacklisted_tokens(pool: &PgPool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM blacklisted_tokens WHERE expires_at <= NOW()")
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

/// 获取所有活跃的黑名单 Token
pub async fn get_active_blacklisted_tokens(pool: &PgPool) -> Result<Vec<(String, String, i64)>> {
    let rows = sqlx::query(
        "SELECT token, reason, extract(epoch from expires_at)::bigint as expires_at 
         FROM blacklisted_tokens 
         WHERE expires_at > NOW() 
         ORDER BY blacklisted_at DESC",
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            (
                row.get("token"),
                row.get::<Option<String>, _>("reason")
                    .unwrap_or_else(|| "No reason".to_string()),
                row.get("expires_at"),
            )
        })
        .collect())
}

/// 写入审计日志
pub async fn create_audit_log(
    pool: &PgPool,
    event_type: &str,
    actor: Option<&str>,
    detail: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO audit_logs (id, event_type, actor, detail)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(event_type)
    .bind(actor)
    .bind(detail)
    .execute(pool)
    .await?;

    Ok(())
}

/// 查询最近审计日志
pub async fn get_recent_audit_logs(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<(String, Option<String>, Option<String>, i64)>> {
    let rows = sqlx::query(
        "SELECT event_type, actor, detail, extract(epoch from created_at)::bigint as created_at
         FROM audit_logs
         ORDER BY created_at DESC
         LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            (
                row.get("event_type"),
                row.get("actor"),
                row.get("detail"),
                row.get("created_at"),
            )
        })
        .collect())
}

/// 分页查询审计日志
pub async fn list_audit_logs(
    pool: &PgPool,
    limit: i64,
    offset: i64,
) -> Result<Vec<(String, Option<String>, Option<String>, i64)>> {
    let rows = sqlx::query(
        "SELECT event_type, actor, detail, extract(epoch from created_at)::bigint as created_at
         FROM audit_logs
         ORDER BY created_at DESC
         LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            (
                row.get("event_type"),
                row.get("actor"),
                row.get("detail"),
                row.get("created_at"),
            )
        })
        .collect())
}

/// 清理旧审计日志
pub async fn cleanup_old_audit_logs(pool: &PgPool, retention_days: i64) -> Result<u64> {
    let result = sqlx::query(
        "DELETE FROM audit_logs
         WHERE created_at < NOW() - ($1::text || ' days')::interval",
    )
    .bind(retention_days)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

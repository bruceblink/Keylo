use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;
use anyhow::Result;

/// 初始化数据库连接池
pub async fn init_db_pool(database_url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;
    
    Ok(pool)
}

/// 运行数据库迁移
pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS clients (
            id TEXT PRIMARY KEY,
            secret TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
            active BOOLEAN NOT NULL DEFAULT TRUE
        );
        
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
        
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at TIMESTAMP NOT NULL,
            revoked BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            revoked_at TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
        );
        
        CREATE TABLE IF NOT EXISTS blacklisted_tokens (
            id TEXT PRIMARY KEY,
            token TEXT NOT NULL UNIQUE,
            reason TEXT,
            blacklisted_at TIMESTAMP NOT NULL DEFAULT NOW(),
            expires_at TIMESTAMP NOT NULL,
            INDEX idx_blacklisted_tokens_token (token),
            INDEX idx_blacklisted_tokens_expires_at (expires_at)
        );
        
        CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client_id ON refresh_tokens(client_id);
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
        CREATE INDEX IF NOT EXISTS idx_blacklisted_tokens_expires_at ON blacklisted_tokens(expires_at);
        "#
    )
    .execute(pool)
    .await?;
    
    Ok(())
}

/// 获取客户端凭证
pub async fn get_client_secret(pool: &PgPool, client_id: &str) -> Result<Option<String>> {
    let row = sqlx::query("SELECT secret FROM clients WHERE id = $1 AND active = TRUE")
        .bind(client_id)
        .fetch_optional(pool)
        .await?;
    
    Ok(row.map(|r| r.get("secret")))
}

/// 创建客户端
pub async fn create_client(
    pool: &PgPool,
    client_id: &str,
    client_secret: &str,
    name: &str,
    description: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO clients (id, secret, name, description) VALUES ($1, $2, $3, $4)"
    )
    .bind(client_id)
    .bind(client_secret)
    .bind(name)
    .bind(description)
    .execute(pool)
    .await?;
    
    Ok(())
}

/// 获取所有活跃客户端
pub async fn get_all_active_clients(pool: &PgPool) -> Result<Vec<(String, String)>> {
    let rows = sqlx::query("SELECT id, secret FROM clients WHERE active = TRUE")
        .fetch_all(pool)
        .await?;
    
    Ok(rows.into_iter()
        .map(|row| (row.get("id"), row.get("secret")))
        .collect())
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
    let rows = sqlx::query(
        "SELECT id, token FROM sessions WHERE user_id = $1 AND expires_at > NOW()"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    
    Ok(rows.into_iter()
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
pub async fn validate_refresh_token(pool: &PgPool, token: &str) -> Result<Option<(String, String)>> {
    let row = sqlx::query(
        "SELECT id, client_id FROM refresh_tokens 
         WHERE token = $1 AND expires_at > NOW() AND revoked = FALSE"
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;
    
    Ok(row.map(|r| (r.get("id"), r.get("client_id"))))
}

/// 撤销 Refresh Token
pub async fn revoke_refresh_token(pool: &PgPool, token_id: &str) -> Result<()> {
    sqlx::query(
        "UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW() WHERE id = $1"
    )
    .bind(token_id)
    .execute(pool)
    .await?;
    
    Ok(())
}

/// 撤销客户端的所有 Refresh Token
pub async fn revoke_client_refresh_tokens(pool: &PgPool, client_id: &str) -> Result<()> {
    sqlx::query(
        "UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW() WHERE client_id = $1"
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
         ON CONFLICT (token) DO NOTHING"
    )
    .bind(format!("bl_{}", token.get(..16).unwrap_or("unknown")))
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
         WHERE token = $1 AND expires_at > NOW() LIMIT 1"
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
         ORDER BY blacklisted_at DESC"
    )
    .fetch_all(pool)
    .await?;
    
    Ok(rows.into_iter()
        .map(|row| (
            row.get("token"),
            row.get::<Option<String>, _>("reason").unwrap_or_else(|| "No reason".to_string()),
            row.get("expires_at")
        ))
        .collect())
}

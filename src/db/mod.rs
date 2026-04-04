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
        
        CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
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

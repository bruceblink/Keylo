use anyhow::Result;
use serde_json::Value;
use sqlx::{PgPool, Postgres, Row};

const SETUP_INITIALIZATION_LOCK_ID: i64 = 4_703_998_017_724_456_961;

pub async fn get_setting(pool: &PgPool, key: &str) -> Result<Option<Value>> {
    let row = sqlx::query("SELECT value FROM system_settings WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await?;

    Ok(row.map(|row| row.get("value")))
}

pub async fn upsert_setting(pool: &PgPool, key: &str, value: &Value) -> Result<()> {
    sqlx::query(
        "INSERT INTO system_settings (key, value)
         VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE
         SET value = EXCLUDED.value,
             updated_at = NOW()",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn setup_completed(pool: &PgPool) -> Result<bool> {
    Ok(get_setting(pool, "setup.completed")
        .await?
        .and_then(|value| value.as_bool())
        .unwrap_or(false))
}

pub async fn mark_setup_completed(pool: &PgPool) -> Result<()> {
    upsert_setting(pool, "setup.completed", &Value::Bool(true)).await?;
    upsert_setting(
        pool,
        "setup.completed_at",
        &Value::String(chrono::Utc::now().to_rfc3339()),
    )
    .await?;

    Ok(())
}

pub struct SetupInitializationLock {
    conn: sqlx::pool::PoolConnection<Postgres>,
}

impl SetupInitializationLock {
    pub async fn release(mut self) -> Result<()> {
        let unlocked: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1)")
            .bind(SETUP_INITIALIZATION_LOCK_ID)
            .fetch_one(&mut *self.conn)
            .await?;

        if !unlocked {
            tracing::warn!("Setup initialization advisory lock was not held during release");
        }

        Ok(())
    }
}

pub async fn try_acquire_setup_initialization_lock(
    pool: &PgPool,
) -> Result<Option<SetupInitializationLock>> {
    let mut conn = pool.acquire().await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(SETUP_INITIALIZATION_LOCK_ID)
        .fetch_one(&mut *conn)
        .await?;

    if locked {
        Ok(Some(SetupInitializationLock { conn }))
    } else {
        Ok(None)
    }
}

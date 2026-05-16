use anyhow::Result;
use serde_json::Value;
use sqlx::{PgPool, Row};

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

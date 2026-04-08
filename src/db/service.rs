use anyhow::Result;
use bcrypt::{hash, verify, DEFAULT_COST};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::models::service::ServiceInfo;

/// 注册服务客户端
pub async fn create_service_client(
    pool: &PgPool,
    service_id: &str,
    service_secret: &str,
    name: &str,
    description: Option<&str>,
    allowed_scopes: &[String],
    allowed_audiences: &[String],
) -> Result<()> {
    let secret_hash = hash(service_secret, DEFAULT_COST)?;
    let scopes: Vec<&str> = allowed_scopes.iter().map(|s| s.as_str()).collect();
    let audiences: Vec<&str> = allowed_audiences.iter().map(|s| s.as_str()).collect();

    sqlx::query(
        "INSERT INTO service_clients
             (service_id, secret_hash, name, description, allowed_scopes, allowed_audiences)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(service_id)
    .bind(&secret_hash)
    .bind(name)
    .bind(description)
    .bind(&scopes)
    .bind(&audiences)
    .execute(pool)
    .await?;

    Ok(())
}

/// 验证服务凭证，返回 (allowed_scopes, allowed_audiences)
pub async fn verify_service_credentials(
    pool: &PgPool,
    service_id: &str,
    service_secret: &str,
) -> Result<Option<(Vec<String>, Vec<String>)>> {
    let row = sqlx::query(
        "SELECT secret_hash, allowed_scopes, allowed_audiences
         FROM service_clients
         WHERE service_id = $1 AND active = TRUE",
    )
    .bind(service_id)
    .fetch_optional(pool)
    .await?;

    match row {
        None => Ok(None),
        Some(r) => {
            let secret_hash: String = r.get("secret_hash");
            if verify(service_secret, &secret_hash)? {
                let scopes: Vec<String> = r.get("allowed_scopes");
                let audiences: Vec<String> = r.get("allowed_audiences");
                Ok(Some((scopes, audiences)))
            } else {
                Ok(None)
            }
        }
    }
}

/// 获取单个服务客户端信息
pub async fn get_service_client(pool: &PgPool, service_id: &str) -> Result<Option<ServiceInfo>> {
    let row = sqlx::query(
        "SELECT service_id, name, description, allowed_scopes, allowed_audiences, active,
                extract(epoch from created_at)::bigint as created_at,
                extract(epoch from updated_at)::bigint as updated_at
         FROM service_clients
         WHERE service_id = $1",
    )
    .bind(service_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| ServiceInfo {
        service_id: r.get("service_id"),
        name: r.get("name"),
        description: r.get("description"),
        allowed_scopes: r.get("allowed_scopes"),
        allowed_audiences: r.get("allowed_audiences"),
        active: r.get("active"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }))
}

/// 列出所有服务客户端
pub async fn list_service_clients(pool: &PgPool) -> Result<Vec<ServiceInfo>> {
    let rows = sqlx::query(
        "SELECT service_id, name, description, allowed_scopes, allowed_audiences, active,
                extract(epoch from created_at)::bigint as created_at,
                extract(epoch from updated_at)::bigint as updated_at
         FROM service_clients
         ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| ServiceInfo {
            service_id: r.get("service_id"),
            name: r.get("name"),
            description: r.get("description"),
            allowed_scopes: r.get("allowed_scopes"),
            allowed_audiences: r.get("allowed_audiences"),
            active: r.get("active"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        })
        .collect())
}

/// 更新服务客户端信息
pub async fn update_service_client(
    pool: &PgPool,
    service_id: &str,
    name: Option<&str>,
    description: Option<&str>,
    allowed_scopes: Option<&[String]>,
    allowed_audiences: Option<&[String]>,
    active: Option<bool>,
) -> Result<bool> {
    let scopes: Option<Vec<&str>> = allowed_scopes.map(|s| s.iter().map(|x| x.as_str()).collect());
    let audiences: Option<Vec<&str>> =
        allowed_audiences.map(|a| a.iter().map(|x| x.as_str()).collect());

    let result = sqlx::query(
        "UPDATE service_clients
         SET name              = COALESCE($2, name),
             description       = COALESCE($3, description),
             allowed_scopes    = COALESCE($4, allowed_scopes),
             allowed_audiences = COALESCE($5, allowed_audiences),
             active            = COALESCE($6, active),
             updated_at        = NOW()
         WHERE service_id = $1",
    )
    .bind(service_id)
    .bind(name)
    .bind(description)
    .bind(scopes)
    .bind(audiences)
    .bind(active)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// 轮换服务密钥
pub async fn rotate_service_secret(
    pool: &PgPool,
    service_id: &str,
    new_secret: &str,
) -> Result<bool> {
    let new_hash = hash(new_secret, DEFAULT_COST)?;

    let result = sqlx::query(
        "UPDATE service_clients
         SET secret_hash = $2, updated_at = NOW()
         WHERE service_id = $1 AND active = TRUE",
    )
    .bind(service_id)
    .bind(&new_hash)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// 生成随机服务密钥
pub fn generate_service_secret() -> String {
    Uuid::new_v4().to_string().replace('-', "")
}

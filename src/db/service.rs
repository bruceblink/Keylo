use anyhow::Result;
use bcrypt::{hash, verify, DEFAULT_COST};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::models::service::{ServiceInfo, ServiceTokenPolicy};

pub enum ServiceCredentialVerification {
    Authorized(ServiceTokenPolicy),
    WrongSecret,
    NotAuthorized,
}

pub struct CreateServiceClientParams<'a> {
    pub service_id: &'a str,
    pub service_secret: &'a str,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub allowed_scopes: &'a [String],
    pub allowed_audiences: &'a [String],
    pub integration_type: &'a str,
    pub introspection_allowed: bool,
    pub token_ttl_seconds: Option<i64>,
    pub owner: Option<&'a str>,
    pub contact: Option<&'a str>,
}

pub struct UpdateServiceClientParams<'a> {
    pub service_id: &'a str,
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
    pub allowed_scopes: Option<&'a [String]>,
    pub allowed_audiences: Option<&'a [String]>,
    pub active: Option<bool>,
    pub integration_type: Option<&'a str>,
    pub introspection_allowed: Option<bool>,
    pub token_ttl_seconds: Option<i64>,
    pub owner: Option<&'a str>,
    pub contact: Option<&'a str>,
}

/// 注册服务客户端
pub async fn create_service_client(
    pool: &PgPool,
    params: CreateServiceClientParams<'_>,
) -> Result<()> {
    let secret_hash = hash(params.service_secret, DEFAULT_COST)?;
    let scopes: Vec<&str> = params.allowed_scopes.iter().map(|s| s.as_str()).collect();
    let audiences: Vec<&str> = params
        .allowed_audiences
        .iter()
        .map(|s| s.as_str())
        .collect();

    sqlx::query(
        "INSERT INTO service_clients
             (service_id, secret_hash, name, description, allowed_scopes, allowed_audiences,
              integration_type, introspection_allowed, token_ttl_seconds, owner, contact)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(params.service_id)
    .bind(&secret_hash)
    .bind(params.name)
    .bind(params.description)
    .bind(&scopes)
    .bind(&audiences)
    .bind(params.integration_type)
    .bind(params.introspection_allowed)
    .bind(params.token_ttl_seconds)
    .bind(params.owner)
    .bind(params.contact)
    .execute(pool)
    .await?;

    Ok(())
}

/// 验证服务凭证并区分未授权与错误密钥
pub async fn verify_service_credentials(
    pool: &PgPool,
    service_id: &str,
    service_secret: &str,
) -> Result<ServiceCredentialVerification> {
    let row = sqlx::query(
        "SELECT secret_hash, allowed_scopes, allowed_audiences, introspection_allowed,
                token_ttl_seconds
         FROM service_clients
         WHERE service_id = $1 AND active = TRUE",
    )
    .bind(service_id)
    .fetch_optional(pool)
    .await?;

    match row {
        None => Ok(ServiceCredentialVerification::NotAuthorized),
        Some(r) => {
            let secret_hash: String = r.get("secret_hash");
            if verify(service_secret, &secret_hash)? {
                let scopes: Vec<String> = r.get("allowed_scopes");
                let audiences: Vec<String> = r.get("allowed_audiences");
                Ok(ServiceCredentialVerification::Authorized(
                    ServiceTokenPolicy {
                        allowed_scopes: scopes,
                        allowed_audiences: audiences,
                        introspection_allowed: r.get("introspection_allowed"),
                        token_ttl_seconds: r.get("token_ttl_seconds"),
                    },
                ))
            } else {
                Ok(ServiceCredentialVerification::WrongSecret)
            }
        }
    }
}

/// 获取单个服务客户端信息
pub async fn get_service_client(pool: &PgPool, service_id: &str) -> Result<Option<ServiceInfo>> {
    let row = sqlx::query(
        "SELECT service_id, name, description, allowed_scopes, allowed_audiences, active,
                integration_type, introspection_allowed, token_ttl_seconds, owner, contact,
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
        integration_type: r.get("integration_type"),
        introspection_allowed: r.get("introspection_allowed"),
        token_ttl_seconds: r.get("token_ttl_seconds"),
        owner: r.get("owner"),
        contact: r.get("contact"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }))
}

/// 列出所有服务客户端
pub async fn list_service_clients(pool: &PgPool) -> Result<Vec<ServiceInfo>> {
    let rows = sqlx::query(
        "SELECT service_id, name, description, allowed_scopes, allowed_audiences, active,
                integration_type, introspection_allowed, token_ttl_seconds, owner, contact,
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
            integration_type: r.get("integration_type"),
            introspection_allowed: r.get("introspection_allowed"),
            token_ttl_seconds: r.get("token_ttl_seconds"),
            owner: r.get("owner"),
            contact: r.get("contact"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        })
        .collect())
}

/// 更新服务客户端信息
pub async fn update_service_client(
    pool: &PgPool,
    params: UpdateServiceClientParams<'_>,
) -> Result<bool> {
    let scopes: Option<Vec<&str>> = params
        .allowed_scopes
        .map(|s| s.iter().map(|x| x.as_str()).collect());
    let audiences: Option<Vec<&str>> = params
        .allowed_audiences
        .map(|a| a.iter().map(|x| x.as_str()).collect());

    let result = sqlx::query(
        "UPDATE service_clients
         SET name              = COALESCE($2, name),
             description       = COALESCE($3, description),
             allowed_scopes    = COALESCE($4, allowed_scopes),
             allowed_audiences = COALESCE($5, allowed_audiences),
             active            = COALESCE($6, active),
             integration_type  = COALESCE($7, integration_type),
             introspection_allowed = COALESCE($8, introspection_allowed),
             token_ttl_seconds = COALESCE($9, token_ttl_seconds),
             owner             = COALESCE($10, owner),
             contact           = COALESCE($11, contact),
             updated_at        = NOW()
         WHERE service_id = $1",
    )
    .bind(params.service_id)
    .bind(params.name)
    .bind(params.description)
    .bind(scopes)
    .bind(audiences)
    .bind(params.active)
    .bind(params.integration_type)
    .bind(params.introspection_allowed)
    .bind(params.token_ttl_seconds)
    .bind(params.owner)
    .bind(params.contact)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn service_introspection_allowed(pool: &PgPool, service_id: &str) -> Result<bool> {
    let row = sqlx::query(
        "SELECT introspection_allowed
         FROM service_clients
         WHERE service_id = $1 AND active = TRUE",
    )
    .bind(service_id)
    .fetch_optional(pool)
    .await?;

    Ok(row
        .map(|r| r.get::<bool, _>("introspection_allowed"))
        .unwrap_or(false))
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

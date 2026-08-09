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

pub const SERVICE_CLIENT_SCOPE_PLATFORM: &str = "platform";
pub const SERVICE_CLIENT_SCOPE_ORGANIZATION: &str = "organization";

/// Records the immutable authorization boundary assigned to one service client.
/// A missing organization means the client is explicitly platform-scoped, not
/// an unfiltered client that may access every organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceClientScope {
    pub scope_kind: String,
    pub organization_id: Option<String>,
}

pub struct CreateServiceClientParams<'a> {
    pub service_id: &'a str,
    pub service_secret: &'a str,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub organization_id: Option<&'a str>,
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

/// Locks and validates the organization before a tenant service client exists.
///
/// Holding the organization row prevents a concurrent disable/archive write
/// from racing an active membership into an organization that is no longer live.
async fn lock_active_service_client_organization(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &str,
) -> Result<()> {
    let organization = sqlx::query(
        r#"
        SELECT status
        FROM organizations
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(organization_id)
    .fetch_optional(&mut **transaction)
    .await?;

    let Some(organization) = organization else {
        anyhow::bail!("organization_service_client_context_inactive");
    };
    let status: String = organization.get("status");
    if status != "active" {
        anyhow::bail!("organization_service_client_context_inactive");
    }

    Ok(())
}

/// Creates a service client and its stable Principal as one database action.
///
/// Organization-scoped clients derive their scope from `organization_id`; the
/// same transaction locks the organization, creates the Principal, and records
/// an active `member` membership so live authorization never sees a half-built
/// machine identity.
pub async fn create_service_client(
    pool: &PgPool,
    params: CreateServiceClientParams<'_>,
) -> Result<()> {
    let secret_hash = hash(params.service_secret, DEFAULT_COST)?;
    let organization_id = match params.organization_id {
        Some(organization_id) => {
            let organization_id = organization_id.trim();
            if organization_id.is_empty() {
                anyhow::bail!("organization_service_client_scope_invalid");
            }
            Some(organization_id)
        }
        None => None,
    };
    let mut transaction = pool.begin().await?;
    if let Some(organization_id) = organization_id {
        lock_active_service_client_organization(&mut transaction, organization_id).await?;
    }
    insert_service_client(&mut transaction, params, organization_id, &secret_hash).await?;
    transaction.commit().await?;

    Ok(())
}

/// Creates a service after locking the delegated owner's live membership.
///
/// The route-level authorization check is useful for early rejection, while
/// this transaction-level check closes the race where the manager is suspended
/// between that check and the service/principal/membership inserts.
pub async fn create_service_client_as_organization_manager(
    pool: &PgPool,
    organization_id: &str,
    actor_principal_id: &str,
    params: CreateServiceClientParams<'_>,
) -> Result<()> {
    if params.organization_id.map(str::trim) != Some(organization_id) {
        anyhow::bail!("organization_service_client_scope_invalid");
    }
    let secret_hash = hash(params.service_secret, DEFAULT_COST)?;
    let mut transaction = pool.begin().await?;
    crate::db::organization::lock_active_organization_manager(
        &mut transaction,
        organization_id,
        actor_principal_id,
    )
    .await?;
    insert_service_client(
        &mut transaction,
        params,
        Some(organization_id),
        &secret_hash,
    )
    .await?;
    transaction.commit().await?;

    Ok(())
}

/// Inserts the service client, its Principal, and its optional organization membership.
///
/// The caller owns the transaction and is responsible for locking the relevant
/// organization and manager context before calling this write-only helper.
async fn insert_service_client(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    params: CreateServiceClientParams<'_>,
    organization_id: Option<&str>,
    secret_hash: &str,
) -> Result<()> {
    let scope_kind = if organization_id.is_some() {
        SERVICE_CLIENT_SCOPE_ORGANIZATION
    } else {
        SERVICE_CLIENT_SCOPE_PLATFORM
    };
    let scopes: Vec<&str> = params
        .allowed_scopes
        .iter()
        .map(|scope| scope.as_str())
        .collect();
    let audiences: Vec<&str> = params
        .allowed_audiences
        .iter()
        .map(|audience| audience.as_str())
        .collect();

    sqlx::query(
        r#"
        INSERT INTO service_clients
            (service_id, secret_hash, name, description, organization_id, scope_kind,
             allowed_scopes, allowed_audiences, integration_type, introspection_allowed,
             token_ttl_seconds, owner, contact)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        "#,
    )
    .bind(params.service_id)
    .bind(secret_hash)
    .bind(params.name)
    .bind(params.description)
    .bind(organization_id)
    .bind(scope_kind)
    .bind(&scopes)
    .bind(&audiences)
    .bind(params.integration_type)
    .bind(params.introspection_allowed)
    .bind(params.token_ttl_seconds)
    .bind(params.owner)
    .bind(params.contact)
    .execute(&mut **transaction)
    .await?;

    let principal = sqlx::query(
        r#"
        INSERT INTO principals (id, principal_type, subject, ref_id, display_name, active)
        VALUES ($1, 'service', $2, $3, $4, TRUE)
        ON CONFLICT (principal_type, ref_id) DO UPDATE
        SET subject = EXCLUDED.subject,
            display_name = EXCLUDED.display_name,
            active = EXCLUDED.active,
            updated_at = NOW()
        RETURNING id
        "#,
    )
    .bind(format!("service-{}", params.service_id))
    .bind(format!("service:{}", params.service_id))
    .bind(params.service_id)
    .bind(params.name)
    .fetch_one(&mut **transaction)
    .await?;
    let principal_id: String = principal.get("id");

    if let Some(organization_id) = organization_id {
        sqlx::query(
            r#"
            INSERT INTO organization_memberships
                (organization_id, principal_id, status, management_role)
            VALUES ($1, $2, 'active', 'member')
            ON CONFLICT (organization_id, principal_id) DO UPDATE
            SET status = EXCLUDED.status,
                management_role = EXCLUDED.management_role,
                updated_at = NOW()
            "#,
        )
        .bind(organization_id)
        .bind(&principal_id)
        .execute(&mut **transaction)
        .await?;
    }

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

/// Returns the persisted tenant boundary for an existing service client.
///
/// The caller must carry this exact value into a service token; `None` is a
/// platform scope and never a wildcard across organization-owned resources.
pub async fn get_service_client_scope(
    pool: &PgPool,
    service_id: &str,
) -> Result<Option<ServiceClientScope>> {
    let row = sqlx::query(
        r#"
        SELECT scope_kind, organization_id
        FROM service_clients
        WHERE service_id = $1
        "#,
    )
    .bind(service_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| ServiceClientScope {
        scope_kind: row.get("scope_kind"),
        organization_id: row.get("organization_id"),
    }))
}

/// 获取单个服务客户端信息
pub async fn get_service_client(pool: &PgPool, service_id: &str) -> Result<Option<ServiceInfo>> {
    let row = sqlx::query(
        "SELECT service_id, name, description, scope_kind, organization_id, allowed_scopes,
                allowed_audiences, active, integration_type, introspection_allowed,
                token_ttl_seconds, owner, contact,
                extract(epoch from created_at)::bigint as created_at,
                extract(epoch from updated_at)::bigint as updated_at
         FROM service_clients
         WHERE service_id = $1",
    )
    .bind(service_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(service_info_from_row))
}

/// Reads one service only when it belongs to the requested organization.
///
/// The organization filter belongs in the database query so a caller cannot
/// turn a globally unique service id into a cross-tenant read.
pub async fn get_service_client_in_organization(
    pool: &PgPool,
    organization_id: &str,
    service_id: &str,
) -> Result<Option<ServiceInfo>> {
    let row = sqlx::query(
        "SELECT service_id, name, description, scope_kind, organization_id, allowed_scopes,
                allowed_audiences, active, integration_type, introspection_allowed,
                token_ttl_seconds, owner, contact,
                extract(epoch from created_at)::bigint as created_at,
                extract(epoch from updated_at)::bigint as updated_at
         FROM service_clients
         WHERE service_id = $1
           AND organization_id = $2
           AND scope_kind = 'organization'",
    )
    .bind(service_id)
    .bind(organization_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(service_info_from_row))
}

/// 列出所有服务客户端
pub async fn list_service_clients(pool: &PgPool) -> Result<Vec<ServiceInfo>> {
    list_service_clients_filtered(pool, None, None, None, i64::MAX, 0).await
}

/// List service clients with exact scope filters and bounded pagination for admin APIs.
#[allow(clippy::too_many_arguments)]
pub async fn list_service_clients_filtered(
    pool: &PgPool,
    organization_id: Option<&str>,
    scope_kind: Option<&str>,
    active: Option<bool>,
    limit: i64,
    offset: i64,
) -> Result<Vec<ServiceInfo>> {
    let rows = sqlx::query(
        "SELECT service_id, name, description, scope_kind, organization_id, allowed_scopes,
                allowed_audiences, active, integration_type, introspection_allowed,
                token_ttl_seconds, owner, contact,
                extract(epoch from created_at)::bigint as created_at,
                extract(epoch from updated_at)::bigint as updated_at
         FROM service_clients
         WHERE ($1::text IS NULL OR organization_id = $1)
           AND ($2::text IS NULL OR scope_kind = $2)
           AND ($3::bool IS NULL OR active = $3)
         ORDER BY created_at DESC, service_id
         LIMIT $4 OFFSET $5",
    )
    .bind(organization_id)
    .bind(scope_kind)
    .bind(active)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(service_info_from_row).collect())
}

/// Lists the service clients whose immutable scope is exactly one organization.
pub async fn list_service_clients_in_organization(
    pool: &PgPool,
    organization_id: &str,
) -> Result<Vec<ServiceInfo>> {
    list_service_clients_in_organization_paginated(pool, organization_id, i64::MAX, 0).await
}

/// List only organization-scoped services with the same bounded pagination contract.
pub async fn list_service_clients_in_organization_paginated(
    pool: &PgPool,
    organization_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<ServiceInfo>> {
    list_service_clients_filtered(
        pool,
        Some(organization_id),
        Some(SERVICE_CLIENT_SCOPE_ORGANIZATION),
        None,
        limit,
        offset,
    )
    .await
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

    if result.rows_affected() > 0 {
        let _ = crate::db::ensure_service_principal(pool, params.service_id).await?;
    }

    Ok(result.rows_affected() > 0)
}

/// Updates a service only after locking the delegated manager's live context.
///
/// A missing row covers both unknown service ids and ids owned by a different
/// organization, so callers can return the same non-disclosing result.
pub async fn update_service_client_as_organization_manager(
    pool: &PgPool,
    organization_id: &str,
    actor_principal_id: &str,
    params: UpdateServiceClientParams<'_>,
) -> Result<bool> {
    let scopes: Option<Vec<&str>> = params
        .allowed_scopes
        .map(|values| values.iter().map(|value| value.as_str()).collect());
    let audiences: Option<Vec<&str>> = params
        .allowed_audiences
        .map(|values| values.iter().map(|value| value.as_str()).collect());

    let mut transaction = pool.begin().await?;
    crate::db::organization::lock_active_organization_manager(
        &mut transaction,
        organization_id,
        actor_principal_id,
    )
    .await?;
    let result = sqlx::query(
        "UPDATE service_clients
         SET name = COALESCE($3, name),
             description = COALESCE($4, description),
             allowed_scopes = COALESCE($5, allowed_scopes),
             allowed_audiences = COALESCE($6, allowed_audiences),
             active = COALESCE($7, active),
             integration_type = COALESCE($8, integration_type),
             introspection_allowed = COALESCE($9, introspection_allowed),
             token_ttl_seconds = COALESCE($10, token_ttl_seconds),
             owner = COALESCE($11, owner),
             contact = COALESCE($12, contact),
             updated_at = NOW()
         WHERE service_id = $1
           AND organization_id = $2
           AND scope_kind = 'organization'",
    )
    .bind(params.service_id)
    .bind(organization_id)
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
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    Ok(result.rows_affected() > 0)
}

pub async fn service_introspection_allowed(pool: &PgPool, service_id: &str) -> Result<bool> {
    let row = sqlx::query(
        "SELECT introspection_allowed
         FROM service_clients
         WHERE service_id = $1
           AND active = TRUE
           AND scope_kind = 'platform'
           AND organization_id IS NULL",
    )
    .bind(service_id)
    .fetch_optional(pool)
    .await?;

    Ok(row
        .map(|r| r.get::<bool, _>("introspection_allowed"))
        .unwrap_or(false))
}

/// Return whether a service still exists and is enabled for tokens issued in its name.
pub async fn service_client_is_active(pool: &PgPool, service_id: &str) -> Result<bool> {
    let row = sqlx::query("SELECT active FROM service_clients WHERE service_id = $1")
        .bind(service_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|row| row.get::<bool, _>("active")).unwrap_or(false))
}

/// Verifies that a service token still names the same live machine identity.
///
/// Both expected values are exact nullable comparisons: a platform token can
/// only match a platform client, and a token without a stable Principal id is
/// rejected instead of being treated as an unrestricted legacy credential.
pub async fn service_token_context_is_active(
    pool: &PgPool,
    service_id: &str,
    expected_principal_id: Option<&str>,
    expected_organization_id: Option<&str>,
) -> Result<bool> {
    let row = sqlx::query(
        r#"
        SELECT 1
        FROM service_clients AS service_client
        INNER JOIN principals AS principal
            ON principal.principal_type = 'service'
           AND principal.ref_id = service_client.service_id
           AND principal.subject = 'service:' || service_client.service_id
        WHERE service_client.service_id = $1
          AND service_client.active = TRUE
          AND principal.active = TRUE
          AND principal.id IS NOT DISTINCT FROM $2::TEXT
          AND service_client.organization_id IS NOT DISTINCT FROM $3::TEXT
          AND (
              (
                  service_client.scope_kind = 'platform'
                  AND service_client.organization_id IS NULL
              )
              OR (
                  service_client.scope_kind = 'organization'
                  AND service_client.organization_id IS NOT NULL
                  AND EXISTS (
                      SELECT 1
                      FROM organizations AS organization
                      INNER JOIN organization_memberships AS membership
                          ON membership.organization_id = organization.id
                         AND membership.principal_id = principal.id
                      WHERE organization.id = service_client.organization_id
                        AND organization.status = 'active'
                        AND membership.status = 'active'
                  )
              )
          )
        LIMIT 1
        "#,
    )
    .bind(service_id)
    .bind(expected_principal_id)
    .bind(expected_organization_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.is_some())
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

    if result.rows_affected() > 0 {
        let _ = crate::db::ensure_service_principal(pool, service_id).await?;
    }

    Ok(result.rows_affected() > 0)
}

/// Rotates a secret only after the organization owner/admin is locked as active.
pub async fn rotate_service_secret_as_organization_manager(
    pool: &PgPool,
    organization_id: &str,
    actor_principal_id: &str,
    service_id: &str,
    new_secret: &str,
) -> Result<bool> {
    let new_hash = hash(new_secret, DEFAULT_COST)?;
    let mut transaction = pool.begin().await?;
    crate::db::organization::lock_active_organization_manager(
        &mut transaction,
        organization_id,
        actor_principal_id,
    )
    .await?;
    let result = sqlx::query(
        "UPDATE service_clients
         SET secret_hash = $3,
             updated_at = NOW()
         WHERE service_id = $1
           AND organization_id = $2
           AND scope_kind = 'organization'
           AND active = TRUE",
    )
    .bind(service_id)
    .bind(organization_id)
    .bind(&new_hash)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    Ok(result.rows_affected() > 0)
}

/// 生成随机服务密钥
pub fn generate_service_secret() -> String {
    Uuid::new_v4().to_string().replace('-', "")
}

/// Converts a service-client result row into the metadata safe for API output.
fn service_info_from_row(row: sqlx::postgres::PgRow) -> ServiceInfo {
    ServiceInfo {
        service_id: row.get("service_id"),
        name: row.get("name"),
        description: row.get("description"),
        scope_kind: row.get("scope_kind"),
        organization_id: row.get("organization_id"),
        allowed_scopes: row.get("allowed_scopes"),
        allowed_audiences: row.get("allowed_audiences"),
        active: row.get("active"),
        integration_type: row.get("integration_type"),
        introspection_allowed: row.get("introspection_allowed"),
        token_ttl_seconds: row.get("token_ttl_seconds"),
        owner: row.get("owner"),
        contact: row.get("contact"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

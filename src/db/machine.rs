use anyhow::Result;
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{NaiveDateTime, Utc};
use sqlx::{PgPool, Row, Transaction};
use uuid::Uuid;

use crate::models::{
    DeviceInfo, MachineCredentialInfo, MachineCredentialSecretResponse, Principal,
    MACHINE_CREDENTIAL_STATUS_ACTIVE, MACHINE_SCOPE_ORGANIZATION, MACHINE_SCOPE_PLATFORM,
};

/// Input needed to create a device Principal inside one transaction.
pub struct CreateDeviceParams<'a> {
    pub device_id: &'a str,
    pub display_name: &'a str,
    pub organization_id: Option<&'a str>,
}

/// Input needed to modify only mutable device fields.
pub struct UpdateDeviceParams<'a> {
    pub display_name: Option<&'a str>,
    pub active: Option<bool>,
}

/// Input needed to persist one new API key without retaining its raw value.
pub struct CreateMachineCredentialParams<'a> {
    pub principal_id: &'a str,
    pub organization_id: Option<&'a str>,
    pub created_by_principal_id: Option<&'a str>,
    pub expires_at: Option<NaiveDateTime>,
    pub allowed_scopes: &'a [String],
    pub allowed_audiences: &'a [String],
}

/// Input used for API-key rotation while retaining the Principal's fixed scope.
pub struct RotateMachineCredentialParams<'a> {
    pub principal_id: &'a str,
    pub organization_id: Option<&'a str>,
    pub key_id: &'a str,
    pub created_by_principal_id: Option<&'a str>,
    pub expires_at: Option<NaiveDateTime>,
    pub allowed_scopes: Option<&'a [String]>,
    pub allowed_audiences: Option<&'a [String]>,
}

/// Principal and immutable scope resolved from service/device storage.
#[derive(Debug, Clone)]
pub struct MachinePrincipalScope {
    pub principal: Principal,
    pub scope_kind: String,
    pub organization_id: Option<String>,
}

/// Authentication state returned only after the raw key and all live guards pass.
#[derive(Debug, Clone)]
pub struct MachineCredentialContext {
    pub credential: MachineCredentialInfo,
    pub principal: Principal,
}

/// Wrong, expired, revoked, cross-tenant, and inactive credentials are unified.
pub enum MachineCredentialVerification {
    Authorized(Box<MachineCredentialContext>),
    Invalid,
}

/// Creates a platform or organization device and records its immutable scope.
pub async fn create_device(pool: &PgPool, params: CreateDeviceParams<'_>) -> Result<DeviceInfo> {
    let organization_id = normalize_organization_id(params.organization_id)?;
    let mut transaction = pool.begin().await?;
    if let Some(organization_id) = organization_id {
        lock_active_organization(&mut transaction, organization_id).await?;
    }
    let device = insert_device(&mut transaction, params, organization_id).await?;
    transaction.commit().await?;
    Ok(device)
}

/// Creates a device only while the delegated owner/admin remains active.
pub async fn create_device_as_organization_manager(
    pool: &PgPool,
    organization_id: &str,
    actor_principal_id: &str,
    params: CreateDeviceParams<'_>,
) -> Result<DeviceInfo> {
    if normalize_organization_id(params.organization_id)? != Some(organization_id) {
        anyhow::bail!("machine_scope_mismatch");
    }
    let mut transaction = pool.begin().await?;
    crate::db::organization::lock_active_organization_manager(
        &mut transaction,
        organization_id,
        actor_principal_id,
    )
    .await?;
    let device = insert_device(&mut transaction, params, Some(organization_id)).await?;
    transaction.commit().await?;
    Ok(device)
}

/// Lists devices by one exact persisted machine scope.
pub async fn list_devices_in_scope(
    pool: &PgPool,
    organization_id: Option<&str>,
) -> Result<Vec<DeviceInfo>> {
    let rows = sqlx::query_as::<_, DeviceInfo>(
        r#"
        SELECT principal.id AS principal_id,
               principal.ref_id AS device_id,
               principal.display_name,
               principal.active,
               device_scope.scope_kind,
               device_scope.organization_id,
               principal.created_at,
               principal.updated_at
        FROM device_principal_scopes AS device_scope
        INNER JOIN principals AS principal ON principal.id = device_scope.principal_id
        WHERE device_scope.organization_id IS NOT DISTINCT FROM $1::TEXT
        ORDER BY principal.created_at DESC, principal.id
        "#,
    )
    .bind(organization_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Return a bounded device page for one exact persisted machine scope.
pub async fn list_devices_in_scope_page(
    pool: &PgPool,
    organization_id: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<(Vec<DeviceInfo>, bool)> {
    let limit = limit.clamp(1, 200);
    let offset = offset.max(0);
    let rows = sqlx::query_as::<_, DeviceInfo>(
        r#"
        SELECT principal.id AS principal_id,
               principal.ref_id AS device_id,
               principal.display_name,
               principal.active,
               device_scope.scope_kind,
               device_scope.organization_id,
               principal.created_at,
               principal.updated_at
        FROM device_principal_scopes AS device_scope
        INNER JOIN principals AS principal ON principal.id = device_scope.principal_id
        WHERE device_scope.organization_id IS NOT DISTINCT FROM $1::TEXT
        ORDER BY principal.created_at DESC, principal.id
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(organization_id)
    .bind(limit + 1)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    let has_more = rows.len() > limit as usize;
    Ok((rows.into_iter().take(limit as usize).collect(), has_more))
}

/// Reads a device only when its immutable scope matches the requested boundary.
pub async fn get_device_in_scope(
    pool: &PgPool,
    organization_id: Option<&str>,
    device_id: &str,
) -> Result<Option<DeviceInfo>> {
    let row = sqlx::query_as::<_, DeviceInfo>(
        r#"
        SELECT principal.id AS principal_id,
               principal.ref_id AS device_id,
               principal.display_name,
               principal.active,
               device_scope.scope_kind,
               device_scope.organization_id,
               principal.created_at,
               principal.updated_at
        FROM device_principal_scopes AS device_scope
        INNER JOIN principals AS principal ON principal.id = device_scope.principal_id
        WHERE principal.principal_type = 'device'
          AND principal.ref_id = $1
          AND device_scope.organization_id IS NOT DISTINCT FROM $2::TEXT
        "#,
    )
    .bind(device_id)
    .bind(organization_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Updates mutable device fields after verifying the exact platform/tenant scope.
pub async fn update_device_in_scope(
    pool: &PgPool,
    organization_id: Option<&str>,
    device_id: &str,
    params: UpdateDeviceParams<'_>,
) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    let updated =
        update_device_in_scope_transaction(&mut transaction, organization_id, device_id, params)
            .await?;
    transaction.commit().await?;
    Ok(updated)
}

/// Updates a device only while its organization manager and target remain live.
pub async fn update_device_as_organization_manager(
    pool: &PgPool,
    organization_id: &str,
    actor_principal_id: &str,
    device_id: &str,
    params: UpdateDeviceParams<'_>,
) -> Result<bool> {
    let Some(device) = get_device_in_scope(pool, Some(organization_id), device_id).await? else {
        return Ok(false);
    };
    let mut transaction = pool.begin().await?;
    crate::db::organization::lock_active_organization_manager_target(
        &mut transaction,
        organization_id,
        actor_principal_id,
        &device.principal_id,
    )
    .await?;
    let updated = update_device_in_scope_transaction(
        &mut transaction,
        Some(organization_id),
        device_id,
        params,
    )
    .await?;
    transaction.commit().await?;
    Ok(updated)
}

/// Creates an API key after live-checking the target machine scope and status.
pub async fn create_machine_credential(
    pool: &PgPool,
    params: CreateMachineCredentialParams<'_>,
) -> Result<MachineCredentialSecretResponse> {
    let mut transaction = pool.begin().await?;
    let response = insert_machine_credential(&mut transaction, params).await?;
    transaction.commit().await?;
    Ok(response)
}

/// Creates a tenant API key while retaining the owner/admin lock to commit.
pub async fn create_machine_credential_as_organization_manager(
    pool: &PgPool,
    organization_id: &str,
    actor_principal_id: &str,
    params: CreateMachineCredentialParams<'_>,
) -> Result<MachineCredentialSecretResponse> {
    if normalize_organization_id(params.organization_id)? != Some(organization_id) {
        anyhow::bail!("machine_scope_mismatch");
    }
    let mut transaction = pool.begin().await?;
    crate::db::organization::lock_active_organization_manager_target(
        &mut transaction,
        organization_id,
        actor_principal_id,
        params.principal_id,
    )
    .await?;
    let response = insert_machine_credential(&mut transaction, params).await?;
    transaction.commit().await?;
    Ok(response)
}

/// Lists safe API-key metadata for a principal only inside its fixed scope.
pub async fn list_machine_credentials_in_scope(
    pool: &PgPool,
    principal_id: &str,
    organization_id: Option<&str>,
) -> Result<Vec<MachineCredentialInfo>> {
    let rows = sqlx::query_as::<_, MachineCredentialInfo>(
        r#"
        SELECT key_id, prefix, principal_id, organization_id, status, expires_at,
               last_used_at, created_by_principal_id, allowed_scopes, allowed_audiences,
               created_at, updated_at
        FROM machine_credentials
        WHERE principal_id = $1
          AND organization_id IS NOT DISTINCT FROM $2::TEXT
        ORDER BY created_at DESC, key_id
        "#,
    )
    .bind(principal_id)
    .bind(organization_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Return a bounded API-key metadata page for one fixed machine scope.
pub async fn list_machine_credentials_in_scope_page(
    pool: &PgPool,
    principal_id: &str,
    organization_id: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<(Vec<MachineCredentialInfo>, bool)> {
    let limit = limit.clamp(1, 200);
    let offset = offset.max(0);
    let rows = sqlx::query_as::<_, MachineCredentialInfo>(
        r#"
        SELECT key_id, prefix, principal_id, organization_id, status, expires_at,
               last_used_at, created_by_principal_id, allowed_scopes, allowed_audiences,
               created_at, updated_at
        FROM machine_credentials
        WHERE principal_id = $1
          AND organization_id IS NOT DISTINCT FROM $2::TEXT
        ORDER BY created_at DESC, key_id
        LIMIT $3 OFFSET $4
        "#,
    )
    .bind(principal_id)
    .bind(organization_id)
    .bind(limit + 1)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    let has_more = rows.len() > limit as usize;
    Ok((rows.into_iter().take(limit as usize).collect(), has_more))
}

/// Rotates by creating a new active key and leaving the old key usable for overlap.
pub async fn rotate_machine_credential(
    pool: &PgPool,
    params: RotateMachineCredentialParams<'_>,
) -> Result<Option<MachineCredentialSecretResponse>> {
    let mut transaction = pool.begin().await?;
    let response = rotate_machine_credential_in_transaction(&mut transaction, params).await?;
    transaction.commit().await?;
    Ok(response)
}

/// Rotates a tenant key while keeping the delegated manager/target locks to commit.
pub async fn rotate_machine_credential_as_organization_manager(
    pool: &PgPool,
    organization_id: &str,
    actor_principal_id: &str,
    params: RotateMachineCredentialParams<'_>,
) -> Result<Option<MachineCredentialSecretResponse>> {
    let mut transaction = pool.begin().await?;
    crate::db::organization::lock_active_organization_manager_target(
        &mut transaction,
        organization_id,
        actor_principal_id,
        params.principal_id,
    )
    .await?;
    let response = rotate_machine_credential_in_transaction(
        &mut transaction,
        RotateMachineCredentialParams {
            principal_id: params.principal_id,
            organization_id: Some(organization_id),
            key_id: params.key_id,
            created_by_principal_id: Some(actor_principal_id),
            expires_at: params.expires_at,
            allowed_scopes: params.allowed_scopes,
            allowed_audiences: params.allowed_audiences,
        },
    )
    .await?;
    transaction.commit().await?;
    Ok(response)
}

async fn rotate_machine_credential_in_transaction(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    params: RotateMachineCredentialParams<'_>,
) -> Result<Option<MachineCredentialSecretResponse>> {
    let existing = locked_credential_in_scope(
        transaction,
        params.principal_id,
        params.organization_id,
        params.key_id,
    )
    .await?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    if existing.status != MACHINE_CREDENTIAL_STATUS_ACTIVE {
        return Ok(None);
    }
    let scopes = params.allowed_scopes.unwrap_or(&existing.allowed_scopes);
    let audiences = params
        .allowed_audiences
        .unwrap_or(&existing.allowed_audiences);
    let response = insert_machine_credential(
        transaction,
        CreateMachineCredentialParams {
            principal_id: params.principal_id,
            organization_id: params.organization_id,
            created_by_principal_id: params.created_by_principal_id,
            expires_at: params.expires_at.or(existing.expires_at),
            allowed_scopes: scopes,
            allowed_audiences: audiences,
        },
    )
    .await?;
    Ok(Some(response))
}

/// Revoke is idempotent and never needs the organization to remain active.
pub async fn revoke_machine_credential_in_scope(
    pool: &PgPool,
    principal_id: &str,
    organization_id: Option<&str>,
    key_id: &str,
    reason: Option<&str>,
) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    let revoked = revoke_machine_credential_in_scope_transaction(
        &mut transaction,
        principal_id,
        organization_id,
        key_id,
        reason,
    )
    .await?;
    transaction.commit().await?;
    Ok(revoked)
}

/// Revokes a tenant key after holding the owner/admin and target locks to commit.
pub async fn revoke_machine_credential_as_organization_manager(
    pool: &PgPool,
    organization_id: &str,
    actor_principal_id: &str,
    principal_id: &str,
    key_id: &str,
    reason: Option<&str>,
) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    crate::db::organization::lock_active_organization_manager_target(
        &mut transaction,
        organization_id,
        actor_principal_id,
        principal_id,
    )
    .await?;
    let revoked = revoke_machine_credential_in_scope_transaction(
        &mut transaction,
        principal_id,
        Some(organization_id),
        key_id,
        reason,
    )
    .await?;
    transaction.commit().await?;
    Ok(revoked)
}

async fn revoke_machine_credential_in_scope_transaction(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    principal_id: &str,
    organization_id: Option<&str>,
    key_id: &str,
    reason: Option<&str>,
) -> Result<bool> {
    let result = sqlx::query(
        r#"
        UPDATE machine_credentials
        SET status = 'revoked',
            revoked_at = COALESCE(revoked_at, NOW()),
            revoke_reason = COALESCE(revoke_reason, $4),
            updated_at = NOW()
        WHERE key_id = $1
          AND principal_id = $2
          AND organization_id IS NOT DISTINCT FROM $3::TEXT
        "#,
    )
    .bind(key_id)
    .bind(principal_id)
    .bind(organization_id)
    .bind(reason)
    .execute(&mut **transaction)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Resolves and revalidates an X-API-Key before an explicitly machine-aware route runs.
pub async fn verify_machine_credential(
    pool: &PgPool,
    raw_api_key: &str,
    required_scope: &str,
    required_audience: &str,
) -> Result<MachineCredentialVerification> {
    let Some((key_id, secret)) = parse_raw_api_key(raw_api_key) else {
        return Ok(MachineCredentialVerification::Invalid);
    };
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        r#"
        SELECT credential.key_id, credential.prefix, credential.secret_hash,
               credential.principal_id, credential.organization_id, credential.status,
               credential.expires_at, credential.last_used_at,
               credential.created_by_principal_id, credential.allowed_scopes,
               credential.allowed_audiences, credential.created_at, credential.updated_at,
               principal.id AS principal_id_value, principal.principal_type,
               principal.subject, principal.ref_id, principal.display_name,
               principal.active AS principal_active, principal.created_at AS principal_created_at,
               principal.updated_at AS principal_updated_at
        FROM machine_credentials AS credential
        INNER JOIN principals AS principal ON principal.id = credential.principal_id
        WHERE credential.key_id = $1
        FOR UPDATE OF credential, principal
        "#,
    )
    .bind(key_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.commit().await?;
        return Ok(MachineCredentialVerification::Invalid);
    };
    let secret_hash: String = row.get("secret_hash");
    if !verify(secret, &secret_hash)? {
        transaction.commit().await?;
        return Ok(MachineCredentialVerification::Invalid);
    }
    let mut credential = machine_credential_from_row(&row);
    let principal = Principal {
        id: row.get("principal_id_value"),
        principal_type: row.get("principal_type"),
        subject: row.get("subject"),
        ref_id: row.get("ref_id"),
        display_name: row.get("display_name"),
        active: row.get("principal_active"),
        created_at: row.get("principal_created_at"),
        updated_at: row.get("principal_updated_at"),
    };
    let currently_valid = credential.status == MACHINE_CREDENTIAL_STATUS_ACTIVE
        && credential
            .expires_at
            .is_none_or(|expires_at| expires_at > Utc::now().naive_utc())
        && credential
            .allowed_scopes
            .iter()
            .any(|scope| scope == required_scope)
        && credential
            .allowed_audiences
            .iter()
            .any(|audience| audience == required_audience || audience == "*")
        && principal.active
        && machine_principal_context_is_active_in_transaction(
            &mut transaction,
            &principal,
            credential.organization_id.as_deref(),
        )
        .await?;
    if !currently_valid {
        transaction.commit().await?;
        return Ok(MachineCredentialVerification::Invalid);
    }
    let last_used_at = Utc::now().naive_utc();
    sqlx::query(
        "UPDATE machine_credentials SET last_used_at = $2, updated_at = $2 WHERE key_id = $1",
    )
    .bind(&credential.key_id)
    .bind(last_used_at)
    .execute(&mut *transaction)
    .await?;
    credential.last_used_at = Some(last_used_at);
    transaction.commit().await?;
    Ok(MachineCredentialVerification::Authorized(Box::new(
        MachineCredentialContext {
            credential,
            principal,
        },
    )))
}

/// Returns an exact live machine scope for management and authorization callers.
pub async fn get_machine_principal_scope(
    pool: &PgPool,
    principal_id: &str,
) -> Result<Option<MachinePrincipalScope>> {
    let principal = crate::db::get_principal_by_id(pool, principal_id).await?;
    let Some(principal) = principal else {
        return Ok(None);
    };
    let scope = match principal.principal_type.as_str() {
        "service" => sqlx::query(
            "SELECT scope_kind, organization_id FROM service_clients WHERE service_id = $1",
        )
        .bind(&principal.ref_id)
        .fetch_optional(pool)
        .await?
        .map(|row| {
            (
                row.get::<String, _>("scope_kind"),
                row.get::<Option<String>, _>("organization_id"),
            )
        }),
        "device" => sqlx::query(
            "SELECT scope_kind, organization_id FROM device_principal_scopes WHERE principal_id = $1",
        )
        .bind(&principal.id)
        .fetch_optional(pool)
        .await?
        .map(|row| {
            (
                row.get::<String, _>("scope_kind"),
                row.get::<Option<String>, _>("organization_id"),
            )
        }),
        _ => None,
    };
    Ok(scope.and_then(|(scope_kind, organization_id)| {
        scope_is_well_formed(&scope_kind, organization_id.as_deref()).then_some(
            MachinePrincipalScope {
                principal,
                scope_kind,
                organization_id,
            },
        )
    }))
}

/// Validates an organization-scoped machine identity's membership at use time.
pub async fn machine_principal_context_is_active(
    pool: &PgPool,
    principal: &Principal,
    organization_id: Option<&str>,
) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    let active = machine_principal_context_is_active_in_transaction(
        &mut transaction,
        principal,
        organization_id,
    )
    .await?;
    transaction.commit().await?;
    Ok(active)
}

async fn insert_device(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    params: CreateDeviceParams<'_>,
    organization_id: Option<&str>,
) -> Result<DeviceInfo> {
    let scope_kind = scope_kind_from_organization(organization_id);
    let principal = sqlx::query_as::<_, Principal>(
        r#"
        INSERT INTO principals (id, principal_type, subject, ref_id, display_name, active)
        VALUES ($1, 'device', $2, $3, $4, TRUE)
        RETURNING id, principal_type, subject, ref_id, display_name, active, created_at, updated_at
        "#,
    )
    .bind(format!("device-{}", params.device_id))
    .bind(format!("device:{}", params.device_id))
    .bind(params.device_id)
    .bind(params.display_name)
    .fetch_one(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO device_principal_scopes (principal_id, scope_kind, organization_id)
         VALUES ($1, $2, $3)",
    )
    .bind(&principal.id)
    .bind(scope_kind)
    .bind(organization_id)
    .execute(&mut **transaction)
    .await?;
    if let Some(organization_id) = organization_id {
        sqlx::query(
            "INSERT INTO organization_memberships
                 (organization_id, principal_id, status, management_role)
             VALUES ($1, $2, 'active', 'member')",
        )
        .bind(organization_id)
        .bind(&principal.id)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(DeviceInfo {
        principal_id: principal.id,
        device_id: principal.ref_id,
        display_name: principal.display_name,
        active: principal.active,
        scope_kind: scope_kind.to_string(),
        organization_id: organization_id.map(str::to_string),
        created_at: principal.created_at,
        updated_at: principal.updated_at,
    })
}

async fn update_device_in_scope_transaction(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    organization_id: Option<&str>,
    device_id: &str,
    params: UpdateDeviceParams<'_>,
) -> Result<bool> {
    let row = sqlx::query(
        "SELECT principal.id
         FROM principals AS principal
         INNER JOIN device_principal_scopes AS device_scope
             ON device_scope.principal_id = principal.id
         WHERE principal.principal_type = 'device'
           AND principal.ref_id = $1
           AND device_scope.organization_id IS NOT DISTINCT FROM $2::TEXT
         FOR UPDATE OF principal, device_scope",
    )
    .bind(device_id)
    .bind(organization_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let principal_id: String = row.get("id");
    let result = sqlx::query(
        "UPDATE principals
         SET display_name = COALESCE($2, display_name),
             active = COALESCE($3, active),
             updated_at = NOW()
         WHERE id = $1",
    )
    .bind(&principal_id)
    .bind(params.display_name)
    .bind(params.active)
    .execute(&mut **transaction)
    .await?;
    Ok(result.rows_affected() > 0)
}

async fn insert_machine_credential(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    params: CreateMachineCredentialParams<'_>,
) -> Result<MachineCredentialSecretResponse> {
    let organization_id = normalize_organization_id(params.organization_id)?;
    lock_machine_principal_scope(transaction, params.principal_id, organization_id).await?;
    let key_id = Uuid::new_v4().simple().to_string();
    let prefix = format!("keylo.{key_id}");
    let secret = Uuid::new_v4().simple().to_string();
    let secret_hash = hash(&secret, DEFAULT_COST)?;
    let scopes: Vec<&str> = params.allowed_scopes.iter().map(String::as_str).collect();
    let audiences: Vec<&str> = params
        .allowed_audiences
        .iter()
        .map(String::as_str)
        .collect();
    let row = sqlx::query(
        r#"
        INSERT INTO machine_credentials
            (key_id, prefix, secret_hash, principal_id, organization_id, expires_at,
             created_by_principal_id, allowed_scopes, allowed_audiences)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING key_id, prefix, principal_id, organization_id, status, expires_at,
                  last_used_at, created_by_principal_id, allowed_scopes, allowed_audiences,
                  created_at, updated_at
        "#,
    )
    .bind(&key_id)
    .bind(&prefix)
    .bind(&secret_hash)
    .bind(params.principal_id)
    .bind(organization_id)
    .bind(params.expires_at)
    .bind(params.created_by_principal_id)
    .bind(&scopes)
    .bind(&audiences)
    .fetch_one(&mut **transaction)
    .await?;
    let credential = machine_credential_from_row(&row);
    Ok(MachineCredentialSecretResponse {
        credential,
        api_key: format!("{prefix}.{secret}"),
    })
}

async fn locked_credential_in_scope(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    principal_id: &str,
    organization_id: Option<&str>,
    key_id: &str,
) -> Result<Option<MachineCredentialInfo>> {
    let row = sqlx::query(
        r#"
        SELECT key_id, prefix, principal_id, organization_id, status, expires_at,
               last_used_at, created_by_principal_id, allowed_scopes, allowed_audiences,
               created_at, updated_at
        FROM machine_credentials
        WHERE key_id = $1
          AND principal_id = $2
          AND organization_id IS NOT DISTINCT FROM $3::TEXT
        FOR UPDATE
        "#,
    )
    .bind(key_id)
    .bind(principal_id)
    .bind(organization_id)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(row.map(|row| machine_credential_from_row(&row)))
}

async fn lock_machine_principal_scope(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    principal_id: &str,
    expected_organization_id: Option<&str>,
) -> Result<MachinePrincipalScope> {
    let principal = sqlx::query_as::<_, Principal>(
        "SELECT id, principal_type, subject, ref_id, display_name, active, created_at, updated_at
         FROM principals WHERE id = $1 FOR UPDATE",
    )
    .bind(principal_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| anyhow::anyhow!("machine_principal_not_found"))?;
    if !principal.active {
        anyhow::bail!("machine_principal_inactive");
    }
    let scope = match principal.principal_type.as_str() {
        "service" => sqlx::query(
            "SELECT scope_kind, organization_id, active
             FROM service_clients WHERE service_id = $1 FOR UPDATE",
        )
        .bind(&principal.ref_id)
        .fetch_optional(&mut **transaction)
        .await?
        .map(|row| {
            (
                row.get::<String, _>("scope_kind"),
                row.get::<Option<String>, _>("organization_id"),
                row.get::<bool, _>("active"),
            )
        }),
        "device" => sqlx::query(
            "SELECT scope_kind, organization_id
             FROM device_principal_scopes WHERE principal_id = $1 FOR UPDATE",
        )
        .bind(&principal.id)
        .fetch_optional(&mut **transaction)
        .await?
        .map(|row| {
            (
                row.get::<String, _>("scope_kind"),
                row.get::<Option<String>, _>("organization_id"),
                true,
            )
        }),
        _ => None,
    }
    .ok_or_else(|| anyhow::anyhow!("machine_principal_type_invalid"))?;
    let (scope_kind, organization_id, machine_active) = scope;
    if !machine_active || !scope_is_well_formed(&scope_kind, organization_id.as_deref()) {
        anyhow::bail!("machine_principal_scope_invalid");
    }
    if organization_id.as_deref() != expected_organization_id {
        anyhow::bail!("machine_scope_mismatch");
    }
    if let Some(organization_id) = expected_organization_id {
        lock_active_organization_membership(transaction, organization_id, &principal.id).await?;
    }
    Ok(MachinePrincipalScope {
        principal,
        scope_kind,
        organization_id,
    })
}

async fn machine_principal_context_is_active_in_transaction(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    principal: &Principal,
    expected_organization_id: Option<&str>,
) -> Result<bool> {
    let scope = match principal.principal_type.as_str() {
        "service" => sqlx::query(
            "SELECT scope_kind, organization_id, active
             FROM service_clients WHERE service_id = $1",
        )
        .bind(&principal.ref_id)
        .fetch_optional(&mut **transaction)
        .await?
        .map(|row| {
            (
                row.get::<String, _>("scope_kind"),
                row.get::<Option<String>, _>("organization_id"),
                row.get::<bool, _>("active"),
            )
        }),
        "device" => sqlx::query(
            "SELECT scope_kind, organization_id FROM device_principal_scopes WHERE principal_id = $1",
        )
        .bind(&principal.id)
        .fetch_optional(&mut **transaction)
        .await?
        .map(|row| {
            (
                row.get::<String, _>("scope_kind"),
                row.get::<Option<String>, _>("organization_id"),
                true,
            )
        }),
        _ => None,
    };
    let Some((scope_kind, organization_id, active)) = scope else {
        return Ok(false);
    };
    if !active
        || !scope_is_well_formed(&scope_kind, organization_id.as_deref())
        || organization_id.as_deref() != expected_organization_id
    {
        return Ok(false);
    }
    let Some(organization_id) = expected_organization_id else {
        return Ok(true);
    };
    let membership = sqlx::query(
        r#"
        SELECT 1
        FROM organizations AS organization
        INNER JOIN organization_memberships AS membership
            ON membership.organization_id = organization.id
           AND membership.principal_id = $2
        WHERE organization.id = $1
          AND organization.status = 'active'
          AND membership.status = 'active'
        "#,
    )
    .bind(organization_id)
    .bind(&principal.id)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(membership.is_some())
}

async fn lock_active_organization(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    organization_id: &str,
) -> Result<()> {
    let row = sqlx::query("SELECT status FROM organizations WHERE id = $1 FOR UPDATE")
        .bind(organization_id)
        .fetch_optional(&mut **transaction)
        .await?;
    if row.is_none_or(|row| row.get::<String, _>("status") != "active") {
        anyhow::bail!("machine_organization_context_inactive");
    }
    Ok(())
}

async fn lock_active_organization_membership(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    organization_id: &str,
    principal_id: &str,
) -> Result<()> {
    lock_active_organization(transaction, organization_id).await?;
    let row = sqlx::query(
        "SELECT status FROM organization_memberships
         WHERE organization_id = $1 AND principal_id = $2 FOR UPDATE",
    )
    .bind(organization_id)
    .bind(principal_id)
    .fetch_optional(&mut **transaction)
    .await?;
    if row.is_none_or(|row| row.get::<String, _>("status") != "active") {
        anyhow::bail!("machine_organization_membership_inactive");
    }
    Ok(())
}

fn normalize_organization_id(organization_id: Option<&str>) -> Result<Option<&str>> {
    match organization_id {
        Some(organization_id) if organization_id.trim().is_empty() => {
            anyhow::bail!("machine_scope_invalid")
        }
        Some(organization_id) => Ok(Some(organization_id.trim())),
        None => Ok(None),
    }
}

fn scope_kind_from_organization(organization_id: Option<&str>) -> &'static str {
    if organization_id.is_some() {
        MACHINE_SCOPE_ORGANIZATION
    } else {
        MACHINE_SCOPE_PLATFORM
    }
}

fn scope_is_well_formed(scope_kind: &str, organization_id: Option<&str>) -> bool {
    matches!(
        (scope_kind, organization_id),
        (MACHINE_SCOPE_PLATFORM, None) | (MACHINE_SCOPE_ORGANIZATION, Some(_))
    )
}

fn parse_raw_api_key(raw_api_key: &str) -> Option<(&str, &str)> {
    let mut components = raw_api_key.split('.');
    let prefix = components.next()?;
    let key_id = components.next()?;
    let secret = components.next()?;
    if prefix != "keylo"
        || key_id.len() != 32
        || secret.len() != 32
        || components.next().is_some()
        || !key_id
            .chars()
            .all(|character| character.is_ascii_hexdigit())
        || !secret
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return None;
    }
    Some((key_id, secret))
}

fn machine_credential_from_row(row: &sqlx::postgres::PgRow) -> MachineCredentialInfo {
    MachineCredentialInfo {
        key_id: row.get("key_id"),
        prefix: row.get("prefix"),
        principal_id: row.get("principal_id"),
        organization_id: row.get("organization_id"),
        status: row.get("status"),
        expires_at: row.get("expires_at"),
        last_used_at: row.get("last_used_at"),
        created_by_principal_id: row.get("created_by_principal_id"),
        allowed_scopes: row.get("allowed_scopes"),
        allowed_audiences: row.get("allowed_audiences"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

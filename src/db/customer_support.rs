use anyhow::Result;
use chrono::{NaiveDateTime, Utc};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Row, Transaction};
use uuid::Uuid;

use crate::models::{
    customer_support_target_type_for_operation, is_valid_customer_support_audit_operation,
    is_valid_customer_support_operation, normalize_customer_support_operations,
    normalize_customer_support_reason, CreateCustomerSupportAccessGrantParams,
    CreateCustomerSupportAuditLogParams, CustomerSupportAccessContext,
    CustomerSupportAccessDecision, CustomerSupportAccessGrant, CustomerSupportAccessGrantDetail,
    CustomerSupportAuditLog, CUSTOMER_SUPPORT_AUDIT_OPERATION_GRANT_CREATED,
    CUSTOMER_SUPPORT_AUDIT_OPERATION_GRANT_REVOKED, CUSTOMER_SUPPORT_AUDIT_OUTCOME_ALLOW,
    CUSTOMER_SUPPORT_AUDIT_OUTCOME_DENY, CUSTOMER_SUPPORT_DENIAL_GRANT_EXPIRED,
    CUSTOMER_SUPPORT_DENIAL_GRANT_NOT_FOUND, CUSTOMER_SUPPORT_DENIAL_GRANT_REVOKED,
    CUSTOMER_SUPPORT_DENIAL_OPERATION_NOT_ALLOWED, CUSTOMER_SUPPORT_DENIAL_ORGANIZATION_MISMATCH,
    CUSTOMER_SUPPORT_DENIAL_ORGANIZATION_NOT_ACTIVE,
    CUSTOMER_SUPPORT_DENIAL_ORGANIZATION_NOT_CUSTOMER,
    CUSTOMER_SUPPORT_DENIAL_ORGANIZATION_NOT_FOUND, CUSTOMER_SUPPORT_DENIAL_PRINCIPAL_MISMATCH,
    CUSTOMER_SUPPORT_DENIAL_PRINCIPAL_NOT_ACTIVE, CUSTOMER_SUPPORT_DENIAL_PRINCIPAL_NOT_FOUND,
    CUSTOMER_SUPPORT_DENIAL_PRINCIPAL_NOT_HUMAN, CUSTOMER_SUPPORT_DENIAL_PRINCIPAL_NOT_INTERNAL,
    CUSTOMER_SUPPORT_DENIAL_ROLE_REQUIRED, CUSTOMER_SUPPORT_ROLE_NAME,
    CUSTOMER_SUPPORT_TARGET_TYPE_ACCESS_GRANT, CUSTOMER_SUPPORT_UNKNOWN_REASON_SNAPSHOT,
};

const MAX_LIST_LIMIT: i64 = 200;

#[derive(Debug)]
struct CustomerSupportPrincipalState {
    principal_type: String,
    principal_active: bool,
    user_active: Option<bool>,
    user_class: Option<String>,
    has_customer_support_role: bool,
}

#[derive(Debug)]
struct ValidatedAuditLogParams {
    grant_id: Option<String>,
    actor_principal_id: Option<String>,
    organization_id: String,
    operation: String,
    reason_snapshot: String,
    target_type: String,
    target_id: Option<String>,
    outcome: String,
    denial_reason: Option<String>,
}

/// Reject blank identifiers before they reach a query with broad matching semantics.
fn required_identifier<'a>(field: &str, value: &'a str) -> Result<&'a str> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("{field}_required");
    }
    Ok(value)
}

fn optional_identifier(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// Preserve the caller's exact filter intent instead of treating a blank value as an unfiltered list.
fn optional_exact_filter<'a>(field: &str, value: Option<&'a str>) -> Result<Option<&'a str>> {
    value
        .map(|value| required_identifier(field, value))
        .transpose()
}

fn grant_from_row(row: &PgRow) -> CustomerSupportAccessGrant {
    CustomerSupportAccessGrant {
        id: row.get("id"),
        support_principal_id: row.get("support_principal_id"),
        organization_id: row.get("organization_id"),
        reason: row.get("reason"),
        granted_by_principal_id: row.get("granted_by_principal_id"),
        granted_at: row.get("granted_at"),
        expires_at: row.get("expires_at"),
        revoked_at: row.get("revoked_at"),
        revoked_by_principal_id: row.get("revoked_by_principal_id"),
        revoke_reason: row.get("revoke_reason"),
    }
}

fn grant_detail_from_row(row: &PgRow) -> CustomerSupportAccessGrantDetail {
    CustomerSupportAccessGrantDetail {
        grant: grant_from_row(row),
        operations: row.get("operations"),
    }
}

fn denied_customer_support_access(
    grant: Option<&CustomerSupportAccessGrantDetail>,
    denial_reason: &str,
) -> CustomerSupportAccessDecision {
    CustomerSupportAccessDecision {
        allowed: false,
        denial_reason: Some(denial_reason.to_string()),
        reason_snapshot: grant
            .map(|grant| grant.grant.reason.clone())
            .unwrap_or_else(|| CUSTOMER_SUPPORT_UNKNOWN_REASON_SNAPSHOT.to_string()),
        context: None,
    }
}

fn allowed_customer_support_access(
    grant: CustomerSupportAccessGrantDetail,
) -> CustomerSupportAccessDecision {
    CustomerSupportAccessDecision {
        allowed: true,
        denial_reason: None,
        reason_snapshot: grant.grant.reason.clone(),
        context: Some(CustomerSupportAccessContext {
            grant_id: grant.grant.id,
            support_principal_id: grant.grant.support_principal_id,
            organization_id: grant.grant.organization_id,
            reason: grant.grant.reason,
            expires_at: grant.grant.expires_at,
            operations: grant.operations,
        }),
    }
}

fn validate_audit_log_params(
    params: &CreateCustomerSupportAuditLogParams<'_>,
) -> Result<ValidatedAuditLogParams> {
    let organization_id = required_identifier(
        "customer_support_audit_organization_id",
        params.organization_id,
    )?;
    let operation = params.operation.trim();
    if !is_valid_customer_support_audit_operation(operation) {
        anyhow::bail!("invalid_customer_support_audit_operation");
    }
    let expected_target_type = customer_support_target_type_for_operation(operation)
        .expect("validated customer support audit operation has a target type");
    let target_type = params.target_type.trim();
    if target_type != expected_target_type {
        anyhow::bail!("invalid_customer_support_audit_target_type");
    }

    let reason_snapshot = normalize_customer_support_reason(params.reason_snapshot)
        .map_err(|reason| anyhow::anyhow!(reason))?;
    let outcome = params.outcome.trim();
    let denial_reason = match outcome {
        CUSTOMER_SUPPORT_AUDIT_OUTCOME_ALLOW => {
            if params
                .denial_reason
                .is_some_and(|reason| !reason.trim().is_empty())
            {
                anyhow::bail!("customer_support_allowed_audit_must_not_have_denial_reason");
            }
            None
        }
        CUSTOMER_SUPPORT_AUDIT_OUTCOME_DENY => {
            let denial_reason = params
                .denial_reason
                .map(str::trim)
                .filter(|reason| !reason.is_empty())
                .ok_or_else(|| anyhow::anyhow!("customer_support_denial_reason_required"))?;
            if denial_reason.chars().count()
                > crate::models::CUSTOMER_SUPPORT_MAX_DENIAL_REASON_LENGTH
            {
                anyhow::bail!("customer_support_denial_reason_too_long");
            }
            Some(denial_reason.to_string())
        }
        _ => anyhow::bail!("invalid_customer_support_audit_outcome"),
    };

    Ok(ValidatedAuditLogParams {
        grant_id: optional_identifier(params.grant_id),
        actor_principal_id: optional_identifier(params.actor_principal_id),
        organization_id: organization_id.to_string(),
        operation: operation.to_string(),
        reason_snapshot,
        target_type: target_type.to_string(),
        target_id: optional_identifier(params.target_id),
        outcome: outcome.to_string(),
        denial_reason,
    })
}

/// Writes one immutable, structured support audit event and propagates failures to the caller.
pub async fn create_customer_support_audit_log(
    pool: &PgPool,
    params: CreateCustomerSupportAuditLogParams<'_>,
) -> Result<CustomerSupportAuditLog> {
    let params = validate_audit_log_params(&params)?;
    let audit_log = sqlx::query_as::<_, CustomerSupportAuditLog>(
        r#"
        INSERT INTO customer_support_audit_logs
            (id, grant_id, actor_principal_id, organization_id, operation,
             reason_snapshot, target_type, target_id, outcome, denial_reason)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id, grant_id, actor_principal_id, organization_id, operation,
                  reason_snapshot, target_type, target_id, outcome, denial_reason, created_at
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(params.grant_id)
    .bind(params.actor_principal_id)
    .bind(params.organization_id)
    .bind(params.operation)
    .bind(params.reason_snapshot)
    .bind(params.target_type)
    .bind(params.target_id)
    .bind(params.outcome)
    .bind(params.denial_reason)
    .fetch_one(pool)
    .await?;

    Ok(audit_log)
}

/// Writes a mandatory audit event on the same transaction as a grant lifecycle update.
async fn create_customer_support_audit_log_in_transaction(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    params: CreateCustomerSupportAuditLogParams<'_>,
) -> Result<CustomerSupportAuditLog> {
    let params = validate_audit_log_params(&params)?;
    let audit_log = sqlx::query_as::<_, CustomerSupportAuditLog>(
        r#"
        INSERT INTO customer_support_audit_logs
            (id, grant_id, actor_principal_id, organization_id, operation,
             reason_snapshot, target_type, target_id, outcome, denial_reason)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id, grant_id, actor_principal_id, organization_id, operation,
                  reason_snapshot, target_type, target_id, outcome, denial_reason, created_at
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(params.grant_id)
    .bind(params.actor_principal_id)
    .bind(params.organization_id)
    .bind(params.operation)
    .bind(params.reason_snapshot)
    .bind(params.target_type)
    .bind(params.target_id)
    .bind(params.outcome)
    .bind(params.denial_reason)
    .fetch_one(&mut **transaction)
    .await?;

    Ok(audit_log)
}

/// Lock and validate an active customer organization before a new support grant is written.
async fn lock_active_customer_organization(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    organization_id: &str,
) -> Result<()> {
    let row = sqlx::query(
        r#"
        SELECT kind, status
        FROM organizations
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(organization_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        anyhow::bail!("customer_support_organization_not_found");
    };
    let kind: String = row.get("kind");
    let status: String = row.get("status");
    if kind != "customer" {
        anyhow::bail!("customer_support_organization_not_customer");
    }
    if status != "active" {
        anyhow::bail!("customer_support_organization_not_active");
    }
    Ok(())
}

/// Lock the human and user records that role writers also lock, then verify the fixed support role.
async fn lock_active_customer_support_principal(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    principal_id: &str,
) -> Result<()> {
    let row = sqlx::query(
        r#"
        SELECT
            principal.principal_type,
            principal.active AS principal_active,
            user_account.active AS user_active,
            user_account.user_class,
            EXISTS (
                SELECT 1
                FROM principal_roles AS principal_role
                INNER JOIN roles AS role ON role.id = principal_role.role_id
                WHERE principal_role.principal_id = principal.id
                  AND role.name = $2
                  AND role.scope = 'platform'
                  AND role.assignable_to = 'user'
                  AND role.system = TRUE
            ) AS has_customer_support_role
        FROM principals AS principal
        INNER JOIN users AS user_account ON user_account.id = principal.ref_id
        WHERE principal.id = $1
        FOR UPDATE OF principal, user_account
        "#,
    )
    .bind(principal_id)
    .bind(CUSTOMER_SUPPORT_ROLE_NAME)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        anyhow::bail!("customer_support_principal_not_found");
    };

    let state = CustomerSupportPrincipalState {
        principal_type: row.get("principal_type"),
        principal_active: row.get("principal_active"),
        user_active: Some(row.get("user_active")),
        user_class: Some(row.get("user_class")),
        has_customer_support_role: row.get("has_customer_support_role"),
    };
    ensure_active_customer_support_principal(&state)
}

/// Enforces every live human/role requirement in one place for create and read paths.
fn ensure_active_customer_support_principal(state: &CustomerSupportPrincipalState) -> Result<()> {
    if state.principal_type != "user" {
        anyhow::bail!("customer_support_principal_requires_user");
    }
    if !state.principal_active || state.user_active != Some(true) {
        anyhow::bail!("customer_support_principal_not_active");
    }
    if state.user_class.as_deref() != Some("internal_employee") {
        anyhow::bail!("customer_support_principal_requires_internal_employee");
    }
    if !state.has_customer_support_role {
        anyhow::bail!("customer_support_role_required");
    }
    Ok(())
}

async fn list_grant_operations_in_transaction(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    grant_id: &str,
) -> Result<Vec<String>> {
    let rows = sqlx::query(
        r#"
        SELECT operation
        FROM customer_support_access_grant_operations
        WHERE grant_id = $1
        ORDER BY operation
        "#,
    )
    .bind(grant_id)
    .fetch_all(&mut **transaction)
    .await?;

    Ok(rows.into_iter().map(|row| row.get("operation")).collect())
}

/// Create a narrow customer-support grant and its required creation audit in one transaction.
///
/// The function grants neither organization membership nor a refresh session. It
/// locks the target organization and support user before checking the fixed role,
/// so a concurrent lifecycle or role change cannot pass a stale validation.
pub async fn create_customer_support_access_grant(
    pool: &PgPool,
    params: CreateCustomerSupportAccessGrantParams<'_>,
) -> Result<CustomerSupportAccessGrantDetail> {
    let support_principal_id =
        required_identifier("customer_support_principal_id", params.support_principal_id)?;
    let organization_id =
        required_identifier("customer_support_organization_id", params.organization_id)?;
    let granted_by_principal_id = required_identifier(
        "customer_support_granted_by_principal_id",
        params.granted_by_principal_id,
    )?;
    let reason = normalize_customer_support_reason(params.reason)
        .map_err(|reason| anyhow::anyhow!(reason))?;
    let operations = normalize_customer_support_operations(params.operations)
        .map_err(|reason| anyhow::anyhow!(reason))?;
    if params.expires_at <= Utc::now().naive_utc() {
        anyhow::bail!("customer_support_access_expiry_must_be_in_future");
    }

    let mut transaction = pool.begin().await?;
    lock_active_customer_organization(&mut transaction, organization_id).await?;
    lock_active_customer_support_principal(&mut transaction, support_principal_id).await?;

    let grant = sqlx::query_as::<_, CustomerSupportAccessGrant>(
        r#"
        INSERT INTO customer_support_access_grants
            (id, support_principal_id, organization_id, reason,
             granted_by_principal_id, granted_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, NOW(), $6)
        RETURNING id, support_principal_id, organization_id, reason,
                  granted_by_principal_id, granted_at, expires_at, revoked_at,
                  revoked_by_principal_id, revoke_reason
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(support_principal_id)
    .bind(organization_id)
    .bind(&reason)
    .bind(granted_by_principal_id)
    .bind(params.expires_at)
    .fetch_one(&mut *transaction)
    .await?;

    for operation in &operations {
        sqlx::query(
            r#"
            INSERT INTO customer_support_access_grant_operations (grant_id, operation)
            VALUES ($1, $2)
            "#,
        )
        .bind(&grant.id)
        .bind(operation)
        .execute(&mut *transaction)
        .await?;
    }

    // This insert is intentionally mandatory: a failed audit rolls back the grant.
    create_customer_support_audit_log_in_transaction(
        &mut transaction,
        CreateCustomerSupportAuditLogParams {
            grant_id: Some(&grant.id),
            actor_principal_id: Some(granted_by_principal_id),
            organization_id,
            operation: CUSTOMER_SUPPORT_AUDIT_OPERATION_GRANT_CREATED,
            reason_snapshot: &reason,
            target_type: CUSTOMER_SUPPORT_TARGET_TYPE_ACCESS_GRANT,
            target_id: Some(&grant.id),
            outcome: CUSTOMER_SUPPORT_AUDIT_OUTCOME_ALLOW,
            denial_reason: None,
        },
    )
    .await?;

    transaction.commit().await?;
    Ok(CustomerSupportAccessGrantDetail { grant, operations })
}

/// Load one support grant with its complete, normalized operation set.
pub async fn get_customer_support_access_grant(
    pool: &PgPool,
    grant_id: &str,
) -> Result<Option<CustomerSupportAccessGrantDetail>> {
    let grant_id = required_identifier("customer_support_grant_id", grant_id)?;
    let row = sqlx::query(
        r#"
        SELECT
            access_grant.id,
            access_grant.support_principal_id,
            access_grant.organization_id,
            access_grant.reason,
            access_grant.granted_by_principal_id,
            access_grant.granted_at,
            access_grant.expires_at,
            access_grant.revoked_at,
            access_grant.revoked_by_principal_id,
            access_grant.revoke_reason,
            COALESCE(
                ARRAY_AGG(operation.operation ORDER BY operation.operation)
                    FILTER (WHERE operation.operation IS NOT NULL),
                ARRAY[]::TEXT[]
            ) AS operations
        FROM customer_support_access_grants AS access_grant
        LEFT JOIN customer_support_access_grant_operations AS operation
            ON operation.grant_id = access_grant.id
        WHERE access_grant.id = $1
        GROUP BY access_grant.id
        "#,
    )
    .bind(grant_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.as_ref().map(grant_detail_from_row))
}

/// List grants with independent exact filters and bounded pagination.
#[allow(clippy::too_many_arguments)]
pub async fn list_customer_support_access_grants(
    pool: &PgPool,
    organization_id: Option<&str>,
    support_principal_id: Option<&str>,
    granted_by_principal_id: Option<&str>,
    include_revoked: bool,
    limit: i64,
    offset: i64,
) -> Result<Vec<CustomerSupportAccessGrantDetail>> {
    let organization_id =
        optional_exact_filter("customer_support_grant_organization_id", organization_id)?;
    let support_principal_id = optional_exact_filter(
        "customer_support_grant_support_principal_id",
        support_principal_id,
    )?;
    let granted_by_principal_id = optional_exact_filter(
        "customer_support_grant_granted_by_principal_id",
        granted_by_principal_id,
    )?;
    let rows = sqlx::query(
        r#"
        SELECT
            access_grant.id,
            access_grant.support_principal_id,
            access_grant.organization_id,
            access_grant.reason,
            access_grant.granted_by_principal_id,
            access_grant.granted_at,
            access_grant.expires_at,
            access_grant.revoked_at,
            access_grant.revoked_by_principal_id,
            access_grant.revoke_reason,
            COALESCE(
                ARRAY_AGG(operation.operation ORDER BY operation.operation)
                    FILTER (WHERE operation.operation IS NOT NULL),
                ARRAY[]::TEXT[]
            ) AS operations
        FROM customer_support_access_grants AS access_grant
        LEFT JOIN customer_support_access_grant_operations AS operation
            ON operation.grant_id = access_grant.id
        WHERE ($1::TEXT IS NULL OR access_grant.organization_id = $1)
          AND ($2::TEXT IS NULL OR access_grant.support_principal_id = $2)
          AND ($3::TEXT IS NULL OR access_grant.granted_by_principal_id = $3)
          AND ($4 OR access_grant.revoked_at IS NULL)
        GROUP BY access_grant.id
        ORDER BY access_grant.granted_at DESC, access_grant.id
        LIMIT $5 OFFSET $6
        "#,
    )
    .bind(organization_id)
    .bind(support_principal_id)
    .bind(granted_by_principal_id)
    .bind(include_revoked)
    .bind(limit.clamp(1, MAX_LIST_LIMIT))
    .bind(offset.max(0))
    .fetch_all(pool)
    .await?;

    Ok(rows.iter().map(grant_detail_from_row).collect())
}

/// Revoke one grant once and record the revocation in the same transaction.
///
/// A repeat revocation returns the stored grant without replacing its original
/// revocation facts or emitting a duplicate audit event; an unknown ID returns
/// `None` so callers can preserve idempotent DELETE semantics.
pub async fn revoke_customer_support_access_grant(
    pool: &PgPool,
    grant_id: &str,
    revoked_by_principal_id: &str,
    revoke_reason: &str,
) -> Result<Option<CustomerSupportAccessGrantDetail>> {
    let grant_id = required_identifier("customer_support_grant_id", grant_id)?;
    let revoked_by_principal_id = required_identifier(
        "customer_support_revoked_by_principal_id",
        revoked_by_principal_id,
    )?;
    let revoke_reason = normalize_customer_support_reason(revoke_reason)
        .map_err(|reason| anyhow::anyhow!(reason))?;

    let mut transaction = pool.begin().await?;
    let grant = sqlx::query_as::<_, CustomerSupportAccessGrant>(
        r#"
        SELECT id, support_principal_id, organization_id, reason,
               granted_by_principal_id, granted_at, expires_at, revoked_at,
               revoked_by_principal_id, revoke_reason
        FROM customer_support_access_grants
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(grant_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(grant) = grant else {
        transaction.commit().await?;
        return Ok(None);
    };

    let operations = list_grant_operations_in_transaction(&mut transaction, &grant.id).await?;
    if grant.revoked_at.is_some() {
        transaction.commit().await?;
        return Ok(Some(CustomerSupportAccessGrantDetail { grant, operations }));
    }

    let grant = sqlx::query_as::<_, CustomerSupportAccessGrant>(
        r#"
        UPDATE customer_support_access_grants
        SET revoked_at = NOW(),
            revoked_by_principal_id = $2,
            revoke_reason = $3
        WHERE id = $1
        RETURNING id, support_principal_id, organization_id, reason,
                  granted_by_principal_id, granted_at, expires_at, revoked_at,
                  revoked_by_principal_id, revoke_reason
        "#,
    )
    .bind(&grant.id)
    .bind(revoked_by_principal_id)
    .bind(&revoke_reason)
    .fetch_one(&mut *transaction)
    .await?;

    // This insert is intentionally mandatory: a failed audit rolls back the revocation.
    create_customer_support_audit_log_in_transaction(
        &mut transaction,
        CreateCustomerSupportAuditLogParams {
            grant_id: Some(&grant.id),
            actor_principal_id: Some(revoked_by_principal_id),
            organization_id: &grant.organization_id,
            operation: CUSTOMER_SUPPORT_AUDIT_OPERATION_GRANT_REVOKED,
            reason_snapshot: &grant.reason,
            target_type: CUSTOMER_SUPPORT_TARGET_TYPE_ACCESS_GRANT,
            target_id: Some(&grant.id),
            outcome: CUSTOMER_SUPPORT_AUDIT_OUTCOME_ALLOW,
            denial_reason: None,
        },
    )
    .await?;

    transaction.commit().await?;
    Ok(Some(CustomerSupportAccessGrantDetail { grant, operations }))
}

async fn get_live_customer_support_principal_state(
    pool: &PgPool,
    principal_id: &str,
) -> Result<Option<CustomerSupportPrincipalState>> {
    let row = sqlx::query(
        r#"
        SELECT
            principal.principal_type,
            principal.active AS principal_active,
            user_account.active AS user_active,
            user_account.user_class,
            EXISTS (
                SELECT 1
                FROM principal_roles AS principal_role
                INNER JOIN roles AS role ON role.id = principal_role.role_id
                WHERE principal_role.principal_id = principal.id
                  AND role.name = $2
                  AND role.scope = 'platform'
                  AND role.assignable_to = 'user'
                  AND role.system = TRUE
            ) AS has_customer_support_role
        FROM principals AS principal
        LEFT JOIN users AS user_account
            ON principal.principal_type = 'user' AND user_account.id = principal.ref_id
        WHERE principal.id = $1
        "#,
    )
    .bind(principal_id)
    .bind(CUSTOMER_SUPPORT_ROLE_NAME)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| CustomerSupportPrincipalState {
        principal_type: row.get("principal_type"),
        principal_active: row.get("principal_active"),
        user_active: row.get("user_active"),
        user_class: row.get("user_class"),
        has_customer_support_role: row.get("has_customer_support_role"),
    }))
}

/// Re-check a grant against live organization, human, and fixed-role state.
///
/// The returned decision never consults organization membership or refresh
/// sessions; the support grant is the sole temporary cross-organization path.
pub async fn get_live_customer_support_access_context(
    pool: &PgPool,
    grant_id: &str,
    support_principal_id: &str,
    organization_id: &str,
) -> Result<CustomerSupportAccessDecision> {
    let grant_id = required_identifier("customer_support_grant_id", grant_id)?;
    let support_principal_id =
        required_identifier("customer_support_principal_id", support_principal_id)?;
    let organization_id = required_identifier("customer_support_organization_id", organization_id)?;
    let grant = get_customer_support_access_grant(pool, grant_id).await?;
    let Some(grant) = grant else {
        return Ok(denied_customer_support_access(
            None,
            CUSTOMER_SUPPORT_DENIAL_GRANT_NOT_FOUND,
        ));
    };

    if grant.grant.support_principal_id != support_principal_id {
        return Ok(denied_customer_support_access(
            Some(&grant),
            CUSTOMER_SUPPORT_DENIAL_PRINCIPAL_MISMATCH,
        ));
    }
    if grant.grant.organization_id != organization_id {
        return Ok(denied_customer_support_access(
            Some(&grant),
            CUSTOMER_SUPPORT_DENIAL_ORGANIZATION_MISMATCH,
        ));
    }
    if grant.grant.revoked_at.is_some() {
        return Ok(denied_customer_support_access(
            Some(&grant),
            CUSTOMER_SUPPORT_DENIAL_GRANT_REVOKED,
        ));
    }
    if grant.grant.expires_at <= Utc::now().naive_utc() {
        return Ok(denied_customer_support_access(
            Some(&grant),
            CUSTOMER_SUPPORT_DENIAL_GRANT_EXPIRED,
        ));
    }

    let organization = sqlx::query("SELECT kind, status FROM organizations WHERE id = $1")
        .bind(organization_id)
        .fetch_optional(pool)
        .await?;
    let Some(organization) = organization else {
        return Ok(denied_customer_support_access(
            Some(&grant),
            CUSTOMER_SUPPORT_DENIAL_ORGANIZATION_NOT_FOUND,
        ));
    };
    let kind: String = organization.get("kind");
    let status: String = organization.get("status");
    if kind != "customer" {
        return Ok(denied_customer_support_access(
            Some(&grant),
            CUSTOMER_SUPPORT_DENIAL_ORGANIZATION_NOT_CUSTOMER,
        ));
    }
    if status != "active" {
        return Ok(denied_customer_support_access(
            Some(&grant),
            CUSTOMER_SUPPORT_DENIAL_ORGANIZATION_NOT_ACTIVE,
        ));
    }

    let principal = get_live_customer_support_principal_state(pool, support_principal_id).await?;
    let Some(principal) = principal else {
        return Ok(denied_customer_support_access(
            Some(&grant),
            CUSTOMER_SUPPORT_DENIAL_PRINCIPAL_NOT_FOUND,
        ));
    };
    if principal.principal_type != "user" {
        return Ok(denied_customer_support_access(
            Some(&grant),
            CUSTOMER_SUPPORT_DENIAL_PRINCIPAL_NOT_HUMAN,
        ));
    }
    if !principal.principal_active || principal.user_active != Some(true) {
        return Ok(denied_customer_support_access(
            Some(&grant),
            CUSTOMER_SUPPORT_DENIAL_PRINCIPAL_NOT_ACTIVE,
        ));
    }
    if principal.user_class.as_deref() != Some("internal_employee") {
        return Ok(denied_customer_support_access(
            Some(&grant),
            CUSTOMER_SUPPORT_DENIAL_PRINCIPAL_NOT_INTERNAL,
        ));
    }
    if !principal.has_customer_support_role {
        return Ok(denied_customer_support_access(
            Some(&grant),
            CUSTOMER_SUPPORT_DENIAL_ROLE_REQUIRED,
        ));
    }

    Ok(allowed_customer_support_access(grant))
}

/// Evaluate one requested support operation against a live grant context.
///
/// Unknown or absent operations deny with the same stable reason so route code
/// can always write an auditable, fail-closed decision without guessing policy.
pub async fn check_customer_support_access_operation(
    pool: &PgPool,
    grant_id: &str,
    support_principal_id: &str,
    organization_id: &str,
    operation: &str,
) -> Result<CustomerSupportAccessDecision> {
    let mut decision = get_live_customer_support_access_context(
        pool,
        grant_id,
        support_principal_id,
        organization_id,
    )
    .await?;
    let Some(context) = decision.context.as_ref() else {
        return Ok(decision);
    };

    if !is_valid_customer_support_operation(operation)
        || !context
            .operations
            .iter()
            .any(|granted| granted == operation)
    {
        decision.allowed = false;
        decision.denial_reason = Some(CUSTOMER_SUPPORT_DENIAL_OPERATION_NOT_ALLOWED.to_string());
    }

    Ok(decision)
}

/// List structured customer-support audit events using only exact filters.
#[allow(clippy::too_many_arguments)]
pub async fn list_customer_support_audit_logs(
    pool: &PgPool,
    organization_id: Option<&str>,
    actor_principal_id: Option<&str>,
    grant_id: Option<&str>,
    operation: Option<&str>,
    outcome: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<CustomerSupportAuditLog>> {
    let organization_id =
        optional_exact_filter("customer_support_audit_organization_id", organization_id)?;
    let actor_principal_id = optional_exact_filter(
        "customer_support_audit_actor_principal_id",
        actor_principal_id,
    )?;
    let grant_id = optional_exact_filter("customer_support_audit_grant_id", grant_id)?;
    let operation = optional_exact_filter("customer_support_audit_operation", operation)?;
    if let Some(operation) = operation {
        if !is_valid_customer_support_audit_operation(operation) {
            anyhow::bail!("invalid_customer_support_audit_operation");
        }
    }
    let outcome = optional_exact_filter("customer_support_audit_outcome", outcome)?;
    if let Some(outcome) = outcome {
        if !matches!(
            outcome,
            CUSTOMER_SUPPORT_AUDIT_OUTCOME_ALLOW | CUSTOMER_SUPPORT_AUDIT_OUTCOME_DENY
        ) {
            anyhow::bail!("invalid_customer_support_audit_outcome");
        }
    }

    let logs = sqlx::query_as::<_, CustomerSupportAuditLog>(
        r#"
        SELECT id, grant_id, actor_principal_id, organization_id, operation,
               reason_snapshot, target_type, target_id, outcome, denial_reason, created_at
        FROM customer_support_audit_logs
        WHERE ($1::TEXT IS NULL OR organization_id = $1)
          AND ($2::TEXT IS NULL OR actor_principal_id = $2)
          AND ($3::TEXT IS NULL OR grant_id = $3)
          AND ($4::TEXT IS NULL OR operation = $4)
          AND ($5::TEXT IS NULL OR outcome = $5)
        ORDER BY created_at DESC, id
        LIMIT $6 OFFSET $7
        "#,
    )
    .bind(organization_id)
    .bind(actor_principal_id)
    .bind(grant_id)
    .bind(operation)
    .bind(outcome)
    .bind(limit.clamp(1, MAX_LIST_LIMIT))
    .bind(offset.max(0))
    .fetch_all(pool)
    .await?;

    Ok(logs)
}

/// Converts the externally supplied expiry into the database timestamp model when callers use epochs.
pub fn customer_support_expiry_from_unix(unix_seconds: i64) -> Result<NaiveDateTime> {
    chrono::DateTime::from_timestamp(unix_seconds, 0)
        .map(|value| value.naive_utc())
        .ok_or_else(|| anyhow::anyhow!("customer_support_expiry_invalid"))
}

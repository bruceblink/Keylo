use anyhow::Result;
use chrono::Local;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::models::{
    is_valid_organization_kind, is_valid_organization_status, Organization, OrganizationMembership,
    OrganizationRoleBinding, Principal, User, ORGANIZATION_KIND_CUSTOMER,
    ORGANIZATION_STATUS_ACTIVE, ROLE_SCOPE_ORGANIZATION, USER_CLASS_EXTERNAL_CUSTOMER,
    USER_CLASS_INTERNAL_EMPLOYEE,
};

const MEMBERSHIP_STATUS_PENDING: &str = "pending";
const MEMBERSHIP_STATUS_ACTIVE: &str = "active";
const MEMBERSHIP_STATUS_SUSPENDED: &str = "suspended";
const MEMBERSHIP_STATUS_REMOVED: &str = "removed";

fn is_valid_membership_status(status: &str) -> bool {
    matches!(
        status,
        MEMBERSHIP_STATUS_PENDING
            | MEMBERSHIP_STATUS_ACTIVE
            | MEMBERSHIP_STATUS_SUSPENDED
            | MEMBERSHIP_STATUS_REMOVED
    )
}

fn required_value(field: &str, value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("{field}_required");
    }
    Ok(value.to_string())
}

/// Creates a tenant boundary with a generated stable identifier.
pub async fn create_organization(
    pool: &PgPool,
    slug: &str,
    name: &str,
    kind: &str,
) -> Result<Organization> {
    let slug = required_value("organization_slug", slug)?;
    let name = required_value("organization_name", name)?;
    let kind = kind.trim();
    if !is_valid_organization_kind(kind) {
        anyhow::bail!("invalid_organization_kind");
    }

    let now = Local::now().naive_utc();
    let organization = sqlx::query_as::<_, Organization>(
        r#"
        INSERT INTO organizations (id, slug, name, kind, status, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $6)
        RETURNING id, slug, name, kind, status, created_at, updated_at
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(slug)
    .bind(name)
    .bind(kind)
    .bind(ORGANIZATION_STATUS_ACTIVE)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(organization)
}

pub async fn get_organization_by_id(
    pool: &PgPool,
    organization_id: &str,
) -> Result<Option<Organization>> {
    Ok(sqlx::query_as::<_, Organization>(
        "SELECT id, slug, name, kind, status, created_at, updated_at FROM organizations WHERE id = $1",
    )
    .bind(organization_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn get_organization_by_slug(pool: &PgPool, slug: &str) -> Result<Option<Organization>> {
    Ok(sqlx::query_as::<_, Organization>(
        "SELECT id, slug, name, kind, status, created_at, updated_at FROM organizations WHERE slug = $1",
    )
    .bind(slug.trim())
    .fetch_optional(pool)
    .await?)
}

pub async fn list_organizations(
    pool: &PgPool,
    status: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<Organization>> {
    if let Some(status) = status {
        if !is_valid_organization_status(status) {
            anyhow::bail!("invalid_organization_status");
        }
    }

    Ok(sqlx::query_as::<_, Organization>(
        r#"
        SELECT id, slug, name, kind, status, created_at, updated_at
        FROM organizations
        WHERE ($1::TEXT IS NULL OR status = $1)
        ORDER BY created_at DESC, id
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(status)
    .bind(limit.clamp(1, 200))
    .bind(offset.max(0))
    .fetch_all(pool)
    .await?)
}

/// Changes organization lifecycle state without ever deleting tenant records.
pub async fn set_organization_status(
    pool: &PgPool,
    organization_id: &str,
    status: &str,
) -> Result<Option<Organization>> {
    let status = status.trim();
    if !is_valid_organization_status(status) {
        anyhow::bail!("invalid_organization_status");
    }

    Ok(sqlx::query_as::<_, Organization>(
        r#"
        UPDATE organizations
        SET status = $2,
            updated_at = $3
        WHERE id = $1
        RETURNING id, slug, name, kind, status, created_at, updated_at
        "#,
    )
    .bind(organization_id)
    .bind(status)
    .bind(Local::now().naive_utc())
    .fetch_optional(pool)
    .await?)
}

/// Inserts or updates one explicit membership; callers decide whether it is an invite or activation.
pub async fn upsert_organization_membership(
    pool: &PgPool,
    organization_id: &str,
    principal_id: &str,
    status: &str,
    invited_by: Option<&str>,
) -> Result<OrganizationMembership> {
    let status = status.trim();
    if !is_valid_membership_status(status) {
        anyhow::bail!("invalid_organization_membership_status");
    }

    let now = Local::now().naive_utc();
    let mut transaction = pool.begin().await?;
    // Lock the organization and principal together so a concurrent disable or
    // principal deactivation cannot race an active membership write.
    let context = sqlx::query(
        r#"
        SELECT organization.status AS organization_status,
               organization.kind AS organization_kind,
               principal.principal_type,
               principal.active AS principal_active,
               user_account.user_class
        FROM organizations AS organization
        INNER JOIN principals AS principal ON principal.id = $2
        LEFT JOIN users AS user_account
            ON principal.principal_type = 'user' AND user_account.id = principal.ref_id
        WHERE organization.id = $1
        FOR UPDATE OF organization, principal
        "#,
    )
    .bind(organization_id)
    .bind(principal_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(context) = context else {
        anyhow::bail!("organization_or_principal_not_found");
    };
    let organization_status: String = context.get("organization_status");
    let organization_kind: String = context.get("organization_kind");
    let principal_type: String = context.get("principal_type");
    let principal_active: bool = context.get("principal_active");
    let user_class: Option<String> = context.get("user_class");
    if organization_status != ORGANIZATION_STATUS_ACTIVE
        && matches!(status, MEMBERSHIP_STATUS_PENDING | MEMBERSHIP_STATUS_ACTIVE)
    {
        anyhow::bail!("organization_not_active");
    }
    if status == MEMBERSHIP_STATUS_ACTIVE && !principal_active {
        anyhow::bail!("principal_not_active");
    }
    if principal_type == "user"
        && user_class.as_deref() == Some(USER_CLASS_EXTERNAL_CUSTOMER)
        && organization_kind != ORGANIZATION_KIND_CUSTOMER
    {
        anyhow::bail!("external_customer_requires_customer_organization");
    }

    let membership = sqlx::query_as::<_, OrganizationMembership>(
        r#"
        INSERT INTO organization_memberships
            (organization_id, principal_id, status, joined_at, invited_by, updated_at)
        VALUES ($1, $2, $3, $4, $5, $4)
        ON CONFLICT (organization_id, principal_id) DO UPDATE
        SET status = EXCLUDED.status,
            invited_by = EXCLUDED.invited_by,
            updated_at = EXCLUDED.updated_at
        RETURNING organization_id, principal_id, status, joined_at, invited_by, updated_at
        "#,
    )
    .bind(organization_id)
    .bind(principal_id)
    .bind(status)
    .bind(now)
    .bind(invited_by)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(membership)
}

pub async fn get_organization_membership(
    pool: &PgPool,
    organization_id: &str,
    principal_id: &str,
) -> Result<Option<OrganizationMembership>> {
    Ok(sqlx::query_as::<_, OrganizationMembership>(
        "SELECT organization_id, principal_id, status, joined_at, invited_by, updated_at FROM organization_memberships WHERE organization_id = $1 AND principal_id = $2",
    )
    .bind(organization_id)
    .bind(principal_id)
    .fetch_optional(pool)
    .await?)
}

/// Binds a role only after confirming the Principal is an active organization member.
pub async fn assign_organization_role(
    pool: &PgPool,
    organization_id: &str,
    principal_id: &str,
    role_id: &str,
    assigned_by: Option<&str>,
) -> Result<OrganizationRoleBinding> {
    let mut transaction = pool.begin().await?;
    // Lock the organization and membership for the whole check-and-bind
    // operation; lifecycle changes then serialize with this assignment.
    let row = sqlx::query(
        r#"
        SELECT p.principal_type, r.assignable_to, r.scope
        FROM organizations AS organization
        INNER JOIN organization_memberships AS membership
            ON membership.organization_id = organization.id
        INNER JOIN principals AS p ON p.id = membership.principal_id
        INNER JOIN roles AS r ON r.id = $3
        WHERE organization.id = $1
          AND organization.status = 'active'
          AND membership.principal_id = $2
          AND membership.status = 'active'
        FOR UPDATE OF organization, membership, p, r
        "#,
    )
    .bind(organization_id)
    .bind(principal_id)
    .bind(role_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        anyhow::bail!("organization_membership_or_role_not_found_or_inactive");
    };
    let principal_type: String = row.get("principal_type");
    let assignable_to: String = row.get("assignable_to");
    let scope: String = row.get("scope");
    if scope != ROLE_SCOPE_ORGANIZATION {
        anyhow::bail!("role_not_organization_scoped");
    }
    crate::db::ensure_role_assignable_to_principal_type(role_id, &assignable_to, &principal_type)?;

    let binding = sqlx::query_as::<_, OrganizationRoleBinding>(
        r#"
        INSERT INTO organization_role_bindings
            (organization_id, principal_id, role_id, scope, assigned_at, assigned_by)
        VALUES ($1, $2, $3, 'organization', $4, $5)
        ON CONFLICT (organization_id, principal_id, role_id) DO UPDATE
        SET assigned_by = EXCLUDED.assigned_by
        RETURNING organization_id, principal_id, role_id, scope, assigned_at, assigned_by
        "#,
    )
    .bind(organization_id)
    .bind(principal_id)
    .bind(role_id)
    .bind(Local::now().naive_utc())
    .bind(assigned_by)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(binding)
}

pub async fn get_organization_role_bindings(
    pool: &PgPool,
    organization_id: &str,
    principal_id: &str,
) -> Result<Vec<OrganizationRoleBinding>> {
    Ok(sqlx::query_as::<_, OrganizationRoleBinding>(
        r#"
        SELECT organization_id, principal_id, role_id, scope, assigned_at, assigned_by
        FROM organization_role_bindings
        WHERE organization_id = $1 AND principal_id = $2
        ORDER BY assigned_at, role_id
        "#,
    )
    .bind(organization_id)
    .bind(principal_id)
    .fetch_all(pool)
    .await?)
}

/// Promotes a bootstrap account and creates its internal membership in one
/// transaction, so a failed organization write cannot leave a half-promoted
/// administrator behind.
pub async fn promote_user_to_internal_employee(
    pool: &PgPool,
    user_id: &str,
    actor: Option<&str>,
) -> Result<Option<User>> {
    let mut transaction = pool.begin().await?;
    let user = sqlx::query_as::<_, User>(
        r#"
        UPDATE users
        SET user_class = $2,
            updated_at = $3
        WHERE id = $1
        RETURNING id, username, email, email_verified, user_class, password_hash, active,
                  created_at, updated_at
        "#,
    )
    .bind(user_id)
    .bind(USER_CLASS_INTERNAL_EMPLOYEE)
    .bind(Local::now().naive_utc())
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(user) = user else {
        transaction.commit().await?;
        return Ok(None);
    };

    let principal = sqlx::query_as::<_, Principal>(
        r#"
        INSERT INTO principals (id, principal_type, subject, ref_id, display_name, active)
        VALUES ($1, 'user', $2, $3, $4, $5)
        ON CONFLICT (principal_type, ref_id) DO UPDATE
        SET subject = EXCLUDED.subject,
            display_name = EXCLUDED.display_name,
            active = EXCLUDED.active,
            updated_at = NOW()
        RETURNING id, principal_type, subject, ref_id, display_name, active, created_at, updated_at
        "#,
    )
    .bind(format!("user-{}", user.id))
    .bind(format!("user:{}", user.id))
    .bind(&user.id)
    .bind(&user.username)
    .bind(user.active)
    .fetch_one(&mut *transaction)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO organization_memberships
            (organization_id, principal_id, status, joined_at, invited_by, updated_at)
        VALUES ('org-internal', $1, 'active', $2, $3, $2)
        ON CONFLICT (organization_id, principal_id) DO UPDATE
        SET status = 'active', invited_by = EXCLUDED.invited_by, updated_at = EXCLUDED.updated_at
        "#,
    )
    .bind(&principal.id)
    .bind(Local::now().naive_utc())
    .bind(actor)
    .execute(&mut *transaction)
    .await?;

    sqlx::query("INSERT INTO audit_logs (id, event_type, actor, detail) VALUES ($1, $2, $3, $4)")
        .bind(Uuid::new_v4().to_string())
        .bind("user.class_changed")
        .bind(actor)
        .bind(format!(
            "user_id={}; user_class={}",
            user.id, user.user_class
        ))
        .execute(&mut *transaction)
        .await?;

    transaction.commit().await?;
    Ok(Some(user))
}

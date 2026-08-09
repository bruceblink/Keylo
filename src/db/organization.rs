use anyhow::Result;
use chrono::Local;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::models::{
    is_valid_organization_kind, is_valid_organization_status, Organization, OrganizationMembership,
    OrganizationRoleBinding, Principal, User, ORGANIZATION_KIND_CUSTOMER,
    ORGANIZATION_MANAGEMENT_ROLE_ADMIN, ORGANIZATION_MANAGEMENT_ROLE_MEMBER,
    ORGANIZATION_MANAGEMENT_ROLE_OWNER, ORGANIZATION_STATUS_ACTIVE, ORGANIZATION_STATUS_ARCHIVED,
    ORGANIZATION_STATUS_DISABLED, ROLE_SCOPE_ORGANIZATION, USER_CLASS_EXTERNAL_CUSTOMER,
    USER_CLASS_INTERNAL_EMPLOYEE,
};

const MEMBERSHIP_STATUS_PENDING: &str = "pending";
const MEMBERSHIP_STATUS_ACTIVE: &str = "active";
const MEMBERSHIP_STATUS_SUSPENDED: &str = "suspended";
const MEMBERSHIP_STATUS_REMOVED: &str = "removed";

fn is_valid_management_role(role: &str) -> bool {
    matches!(
        role,
        ORGANIZATION_MANAGEMENT_ROLE_MEMBER
            | ORGANIZATION_MANAGEMENT_ROLE_ADMIN
            | ORGANIZATION_MANAGEMENT_ROLE_OWNER
    )
}

#[derive(Debug, Clone)]
struct LockedOrganizationManagerContext {
    target: Principal,
    target_membership: Option<OrganizationMembership>,
    target_user_active: Option<bool>,
    actor_management_role: String,
}

/// Captures the stored state that preceded an organization lifecycle update.
///
/// The route layer uses this value to write an audit record that explains both
/// sides of a transition without doing a second, race-prone status lookup.
#[derive(Debug, Clone)]
pub struct OrganizationStatusChange {
    pub previous_status: String,
    pub organization: Organization,
}

fn is_valid_membership_status(status: &str) -> bool {
    matches!(
        status,
        MEMBERSHIP_STATUS_PENDING
            | MEMBERSHIP_STATUS_ACTIVE
            | MEMBERSHIP_STATUS_SUSPENDED
            | MEMBERSHIP_STATUS_REMOVED
    )
}

/// Allows only reversible lifecycle steps and makes archive restoration explicit.
pub fn is_valid_organization_status_transition(current: &str, next: &str) -> bool {
    current == next
        || matches!(
            (current, next),
            (ORGANIZATION_STATUS_ACTIVE, ORGANIZATION_STATUS_DISABLED)
                | (ORGANIZATION_STATUS_ACTIVE, ORGANIZATION_STATUS_ARCHIVED)
                | (ORGANIZATION_STATUS_DISABLED, ORGANIZATION_STATUS_ACTIVE)
                | (ORGANIZATION_STATUS_DISABLED, ORGANIZATION_STATUS_ARCHIVED)
                | (ORGANIZATION_STATUS_ARCHIVED, ORGANIZATION_STATUS_ACTIVE)
        )
}

fn required_value(field: &str, value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("{field}_required");
    }
    Ok(value.to_string())
}

/// Locks one organization, the manager's human Principal, and the target rows
/// in a deterministic order before a delegated write is evaluated.
///
/// Management authority is intentionally stored on the membership itself;
/// organization role bindings remain data for later authorization work and do
/// not grant delegated-administration privileges here.
async fn lock_organization_manager_context(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &str,
    actor_principal_id: &str,
    target_principal_id: &str,
) -> Result<LockedOrganizationManagerContext> {
    let organization = sqlx::query_as::<_, Organization>(
        r#"
        SELECT id, slug, name, kind, status, created_at, updated_at
        FROM organizations
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(organization_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| anyhow::anyhow!("organization_not_found"))?;
    if organization.status != ORGANIZATION_STATUS_ACTIVE {
        anyhow::bail!("organization_not_active");
    }

    // Lock both Principal rows in a stable database order so two managers
    // updating one another cannot acquire caller/target locks in reverse order.
    let principals = sqlx::query_as::<_, Principal>(
        r#"
        SELECT id, principal_type, subject, ref_id, display_name, active, created_at, updated_at
        FROM principals
        WHERE id = $1 OR id = $2
        ORDER BY id
        FOR UPDATE
        "#,
    )
    .bind(actor_principal_id)
    .bind(target_principal_id)
    .fetch_all(&mut **transaction)
    .await?;
    let actor = principals
        .iter()
        .find(|principal| principal.id == actor_principal_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("organization_manager_principal_not_found"))?;
    let target = principals
        .iter()
        .find(|principal| principal.id == target_principal_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("organization_target_principal_not_found"))?;

    let mut user_ids = principals
        .iter()
        .filter(|principal| principal.principal_type == "user")
        .map(|principal| principal.ref_id.clone())
        .collect::<Vec<_>>();
    user_ids.sort();
    user_ids.dedup();
    let mut user_rows = Vec::with_capacity(user_ids.len());
    for user_id in user_ids {
        let row = sqlx::query("SELECT id, active, user_class FROM users WHERE id = $1 FOR UPDATE")
            .bind(&user_id)
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or_else(|| anyhow::anyhow!("organization_principal_user_not_found"))?;
        user_rows.push((
            row.get::<String, _>("id"),
            row.get::<bool, _>("active"),
            row.get::<String, _>("user_class"),
        ));
    }

    let memberships = sqlx::query_as::<_, OrganizationMembership>(
        r#"
        SELECT organization_id, principal_id, status, joined_at, invited_by,
               management_role, updated_at
        FROM organization_memberships
        WHERE organization_id = $1
          AND (principal_id = $2 OR principal_id = $3)
        ORDER BY principal_id
        FOR UPDATE
        "#,
    )
    .bind(organization_id)
    .bind(actor_principal_id)
    .bind(target_principal_id)
    .fetch_all(&mut **transaction)
    .await?;
    let actor_membership = memberships
        .iter()
        .find(|membership| membership.principal_id == actor_principal_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("organization_manager_membership_not_found"))?;
    let target_membership = memberships
        .iter()
        .find(|membership| membership.principal_id == target_principal_id)
        .cloned();

    if actor.principal_type != "user" {
        anyhow::bail!("organization_manager_requires_user_principal");
    }
    let Some((_, actor_user_active, actor_user_class)) = user_rows
        .iter()
        .find(|(user_id, _, _)| user_id == &actor.ref_id)
    else {
        anyhow::bail!("organization_manager_user_not_found");
    };
    if !actor.active || !*actor_user_active {
        anyhow::bail!("organization_manager_principal_inactive");
    }
    if !matches!(
        actor_user_class.as_str(),
        USER_CLASS_INTERNAL_EMPLOYEE | USER_CLASS_EXTERNAL_CUSTOMER
    ) {
        anyhow::bail!("organization_manager_user_class_invalid");
    }
    if actor_user_class == USER_CLASS_EXTERNAL_CUSTOMER
        && organization.kind != ORGANIZATION_KIND_CUSTOMER
    {
        anyhow::bail!("external_customer_requires_customer_organization");
    }
    if actor_membership.status != MEMBERSHIP_STATUS_ACTIVE {
        anyhow::bail!("organization_manager_membership_not_active");
    }
    if !matches!(
        actor_membership.management_role.as_str(),
        ORGANIZATION_MANAGEMENT_ROLE_ADMIN | ORGANIZATION_MANAGEMENT_ROLE_OWNER
    ) {
        anyhow::bail!("organization_manager_role_required");
    }

    let target_user_active = if target.principal_type == "user" {
        let Some((_, target_user_active, target_user_class)) = user_rows
            .iter()
            .find(|(user_id, _, _)| user_id == &target.ref_id)
        else {
            anyhow::bail!("organization_target_user_not_found");
        };
        if !matches!(
            target_user_class.as_str(),
            USER_CLASS_INTERNAL_EMPLOYEE | USER_CLASS_EXTERNAL_CUSTOMER
        ) {
            anyhow::bail!("organization_target_user_class_invalid");
        }
        if target_user_class == USER_CLASS_EXTERNAL_CUSTOMER
            && organization.kind != ORGANIZATION_KIND_CUSTOMER
        {
            anyhow::bail!("external_customer_requires_customer_organization");
        }
        Some(*target_user_active)
    } else {
        None
    };

    let actor_management_role = actor_membership.management_role.clone();
    Ok(LockedOrganizationManagerContext {
        target,
        target_membership,
        target_user_active,
        actor_management_role,
    })
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
///
/// The status row stays locked for the check-and-write sequence so concurrent
/// callers cannot bypass the lifecycle transition rules.
pub async fn set_organization_status(
    pool: &PgPool,
    organization_id: &str,
    status: &str,
) -> Result<Option<OrganizationStatusChange>> {
    let status = status.trim();
    if !is_valid_organization_status(status) {
        anyhow::bail!("invalid_organization_status");
    }

    let mut transaction = pool.begin().await?;
    let current_status = sqlx::query("SELECT status FROM organizations WHERE id = $1 FOR UPDATE")
        .bind(organization_id)
        .fetch_optional(&mut *transaction)
        .await?
        .map(|row| row.get::<String, _>("status"));
    let Some(previous_status) = current_status else {
        transaction.commit().await?;
        return Ok(None);
    };
    if !is_valid_organization_status_transition(&previous_status, status) {
        anyhow::bail!("invalid_organization_status_transition");
    }

    let organization = sqlx::query_as::<_, Organization>(
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
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;

    Ok(Some(OrganizationStatusChange {
        previous_status,
        organization,
    }))
}

/// Inserts or updates one explicit membership; callers decide whether it is an invite or activation.
pub async fn upsert_organization_membership(
    pool: &PgPool,
    organization_id: &str,
    principal_id: &str,
    status: &str,
    invited_by: Option<&str>,
    management_role: Option<&str>,
) -> Result<OrganizationMembership> {
    let status = status.trim();
    if !is_valid_membership_status(status) {
        anyhow::bail!("invalid_organization_membership_status");
    }
    let management_role = management_role.map(str::trim);
    if let Some(role) = management_role {
        if !is_valid_management_role(role) {
            anyhow::bail!("invalid_organization_management_role");
        }
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
    if management_role.is_some_and(|role| role != ORGANIZATION_MANAGEMENT_ROLE_MEMBER)
        && (principal_type != "user"
            || !matches!(
                user_class.as_deref(),
                Some(USER_CLASS_INTERNAL_EMPLOYEE) | Some(USER_CLASS_EXTERNAL_CUSTOMER)
            ))
    {
        anyhow::bail!("organization_management_role_requires_user_principal");
    }

    let membership = sqlx::query_as::<_, OrganizationMembership>(
        r#"
        INSERT INTO organization_memberships
            (organization_id, principal_id, status, joined_at, invited_by, management_role, updated_at)
        VALUES ($1, $2, $3, $4, $5, COALESCE($6, 'member'), $4)
        ON CONFLICT (organization_id, principal_id) DO UPDATE
        SET status = EXCLUDED.status,
            invited_by = EXCLUDED.invited_by,
            management_role = COALESCE($6, organization_memberships.management_role),
            updated_at = EXCLUDED.updated_at
        RETURNING organization_id, principal_id, status, joined_at, invited_by,
                  management_role, updated_at
        "#,
    )
    .bind(organization_id)
    .bind(principal_id)
    .bind(status)
    .bind(now)
    .bind(invited_by)
    .bind(management_role)
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
        "SELECT organization_id, principal_id, status, joined_at, invited_by, management_role, updated_at FROM organization_memberships WHERE organization_id = $1 AND principal_id = $2",
    )
    .bind(organization_id)
    .bind(principal_id)
    .fetch_optional(pool)
    .await?)
}

/// Lists memberships for one organization while keeping pagination bounded.
pub async fn list_organization_memberships(
    pool: &PgPool,
    organization_id: &str,
    status: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<OrganizationMembership>> {
    if let Some(status) = status {
        if !is_valid_membership_status(status) {
            anyhow::bail!("invalid_organization_membership_status");
        }
    }

    Ok(sqlx::query_as::<_, OrganizationMembership>(
        r#"
        SELECT organization_id, principal_id, status, joined_at, invited_by,
               management_role, updated_at
        FROM organization_memberships
        WHERE organization_id = $1
          AND ($2::TEXT IS NULL OR status = $2)
        ORDER BY joined_at, principal_id
        LIMIT $3 OFFSET $4
        "#,
    )
    .bind(organization_id)
    .bind(status)
    .bind(limit.clamp(1, 200))
    .bind(offset.max(0))
    .fetch_all(pool)
    .await?)
}

/// Invites or updates a member on behalf of an active organization owner/admin.
///
/// The manager check, target lookup, and idempotent upsert share one transaction
/// so a caller cannot race a membership suspension or organization shutdown.
pub async fn upsert_organization_membership_as_manager(
    pool: &PgPool,
    organization_id: &str,
    actor_principal_id: &str,
    target_principal_id: &str,
    status: &str,
    management_role: Option<&str>,
) -> Result<OrganizationMembership> {
    let status = status.trim();
    if !is_valid_membership_status(status) {
        anyhow::bail!("invalid_organization_membership_status");
    }
    let management_role = management_role.map(str::trim);
    if let Some(role) = management_role {
        if !is_valid_management_role(role) {
            anyhow::bail!("invalid_organization_management_role");
        }
    }

    let mut transaction = pool.begin().await?;
    let context = lock_organization_manager_context(
        &mut transaction,
        organization_id,
        actor_principal_id,
        target_principal_id,
    )
    .await?;
    if status == MEMBERSHIP_STATUS_ACTIVE
        && (!context.target.active || context.target_user_active == Some(false))
    {
        anyhow::bail!("organization_target_principal_inactive");
    }
    if context.target.principal_type != "user"
        && management_role.is_some_and(|role| role != ORGANIZATION_MANAGEMENT_ROLE_MEMBER)
    {
        anyhow::bail!("organization_management_role_requires_user_principal");
    }
    if context.actor_management_role == ORGANIZATION_MANAGEMENT_ROLE_ADMIN
        && management_role == Some(ORGANIZATION_MANAGEMENT_ROLE_OWNER)
    {
        anyhow::bail!("organization_owner_role_required");
    }
    if context.actor_management_role == ORGANIZATION_MANAGEMENT_ROLE_ADMIN
        && context
            .target_membership
            .as_ref()
            .is_some_and(|membership| {
                membership.management_role == ORGANIZATION_MANAGEMENT_ROLE_OWNER
            })
        && (status != MEMBERSHIP_STATUS_ACTIVE
            || management_role.is_some_and(|role| role != ORGANIZATION_MANAGEMENT_ROLE_OWNER))
    {
        anyhow::bail!("organization_owner_role_required");
    }
    if status == MEMBERSHIP_STATUS_PENDING {
        // A retrying invitation must not downgrade an already active member.
        if let Some(membership) = context
            .target_membership
            .clone()
            .filter(|membership| membership.status == MEMBERSHIP_STATUS_ACTIVE)
        {
            transaction.commit().await?;
            return Ok(membership);
        }
    }

    let now = Local::now().naive_utc();
    let membership = sqlx::query_as::<_, OrganizationMembership>(
        r#"
        INSERT INTO organization_memberships
            (organization_id, principal_id, status, joined_at, invited_by,
             management_role, updated_at)
        VALUES ($1, $2, $3, $4, $5, COALESCE($6, 'member'), $4)
        ON CONFLICT (organization_id, principal_id) DO UPDATE
        SET status = EXCLUDED.status,
            invited_by = EXCLUDED.invited_by,
            management_role = COALESCE($6, organization_memberships.management_role),
            updated_at = EXCLUDED.updated_at
        RETURNING organization_id, principal_id, status, joined_at, invited_by,
                  management_role, updated_at
        "#,
    )
    .bind(organization_id)
    .bind(target_principal_id)
    .bind(status)
    .bind(now)
    .bind(actor_principal_id)
    .bind(management_role)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(membership)
}

/// Creates or refreshes a pending invitation without granting an active context.
pub async fn invite_organization_member_as_manager(
    pool: &PgPool,
    organization_id: &str,
    actor_principal_id: &str,
    target_principal_id: &str,
    management_role: Option<&str>,
) -> Result<OrganizationMembership> {
    upsert_organization_membership_as_manager(
        pool,
        organization_id,
        actor_principal_id,
        target_principal_id,
        MEMBERSHIP_STATUS_PENDING,
        management_role,
    )
    .await
}

/// Applies an idempotent membership-status update under owner/admin authority.
pub async fn update_organization_membership_as_manager(
    pool: &PgPool,
    organization_id: &str,
    actor_principal_id: &str,
    target_principal_id: &str,
    status: &str,
    management_role: Option<&str>,
) -> Result<OrganizationMembership> {
    upsert_organization_membership_as_manager(
        pool,
        organization_id,
        actor_principal_id,
        target_principal_id,
        status,
        management_role,
    )
    .await
}

/// Accepts a pending invitation for the authenticated Principal exactly once.
///
/// A repeated join is an idempotent read of the active membership; suspended,
/// removed, or missing invitations fail closed instead of creating access.
pub async fn join_organization_membership(
    pool: &PgPool,
    organization_id: &str,
    principal_id: &str,
) -> Result<OrganizationMembership> {
    let mut transaction = pool.begin().await?;
    let organization = sqlx::query_as::<_, Organization>(
        r#"
        SELECT id, slug, name, kind, status, created_at, updated_at
        FROM organizations
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(organization_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| anyhow::anyhow!("organization_not_found"))?;
    if organization.status != ORGANIZATION_STATUS_ACTIVE {
        anyhow::bail!("organization_not_active");
    }
    let principal = sqlx::query_as::<_, Principal>(
        r#"
        SELECT id, principal_type, subject, ref_id, display_name, active, created_at, updated_at
        FROM principals
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(principal_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| anyhow::anyhow!("organization_target_principal_not_found"))?;
    if principal.principal_type != "user" {
        anyhow::bail!("organization_join_requires_user_principal");
    }
    let user = sqlx::query("SELECT active, user_class FROM users WHERE id = $1 FOR UPDATE")
        .bind(&principal.ref_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| anyhow::anyhow!("organization_target_user_not_found"))?;
    let user_active: bool = user.get("active");
    let user_class: String = user.get("user_class");
    if !principal.active || !user_active {
        anyhow::bail!("organization_target_principal_inactive");
    }
    if !matches!(
        user_class.as_str(),
        USER_CLASS_INTERNAL_EMPLOYEE | USER_CLASS_EXTERNAL_CUSTOMER
    ) {
        anyhow::bail!("organization_target_user_class_invalid");
    }
    if user_class == USER_CLASS_EXTERNAL_CUSTOMER && organization.kind != ORGANIZATION_KIND_CUSTOMER
    {
        anyhow::bail!("external_customer_requires_customer_organization");
    }
    let membership = sqlx::query_as::<_, OrganizationMembership>(
        r#"
        SELECT organization_id, principal_id, status, joined_at, invited_by,
               management_role, updated_at
        FROM organization_memberships
        WHERE organization_id = $1 AND principal_id = $2
        FOR UPDATE
        "#,
    )
    .bind(organization_id)
    .bind(principal_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| anyhow::anyhow!("organization_invitation_not_found"))?;
    if membership.status == MEMBERSHIP_STATUS_ACTIVE {
        transaction.commit().await?;
        return Ok(membership);
    }
    if membership.status != MEMBERSHIP_STATUS_PENDING {
        anyhow::bail!("organization_membership_not_joinable");
    }

    let joined = sqlx::query_as::<_, OrganizationMembership>(
        r#"
        UPDATE organization_memberships
        SET status = 'active', updated_at = $3
        WHERE organization_id = $1 AND principal_id = $2 AND status = 'pending'
        RETURNING organization_id, principal_id, status, joined_at, invited_by,
                  management_role, updated_at
        "#,
    )
    .bind(organization_id)
    .bind(principal_id)
    .bind(Local::now().naive_utc())
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(joined)
}

/// Resolves one currently usable membership without treating organization roles
/// as authorization. Callers can use this for organization-context checks.
pub async fn get_active_organization_membership(
    pool: &PgPool,
    organization_id: &str,
    principal_id: &str,
) -> Result<Option<OrganizationMembership>> {
    Ok(sqlx::query_as::<_, OrganizationMembership>(
        r#"
        SELECT membership.organization_id, membership.principal_id, membership.status,
               membership.joined_at, membership.invited_by, membership.management_role,
               membership.updated_at
        FROM organization_memberships AS membership
        INNER JOIN organizations AS organization
            ON organization.id = membership.organization_id
        INNER JOIN principals AS principal ON principal.id = membership.principal_id
        LEFT JOIN users AS user_account
            ON principal.principal_type = 'user' AND user_account.id = principal.ref_id
        WHERE membership.organization_id = $1
          AND membership.principal_id = $2
          AND organization.status = 'active'
          AND membership.status = 'active'
          AND principal.active = TRUE
          AND (
              principal.principal_type <> 'user'
              OR (
                  user_account.active = TRUE
                  AND user_account.user_class IN ('internal_employee', 'external_customer')
                  AND (
                      user_account.user_class <> 'external_customer'
                      OR organization.kind = 'customer'
                  )
              )
          )
        "#,
    )
    .bind(organization_id)
    .bind(principal_id)
    .fetch_optional(pool)
    .await?)
}

/// Requires an active human owner/admin membership for a delegated read path.
///
/// This uses the same locked validation as write helpers so a manager cannot be
/// authorized from stale membership data while a concurrent lifecycle change runs.
pub async fn require_organization_manager(
    pool: &PgPool,
    organization_id: &str,
    actor_principal_id: &str,
) -> Result<OrganizationMembership> {
    let mut transaction = pool.begin().await?;
    let context = lock_organization_manager_context(
        &mut transaction,
        organization_id,
        actor_principal_id,
        actor_principal_id,
    )
    .await?;
    let membership = context
        .target_membership
        .ok_or_else(|| anyhow::anyhow!("organization_manager_membership_not_found"))?;
    transaction.commit().await?;
    Ok(membership)
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

/// Stores an organization-scoped role binding after the caller passes the
/// separate membership-management check. The binding is not read by general
/// authorization until the organization authorization engine is introduced.
pub async fn assign_organization_role_as_manager(
    pool: &PgPool,
    organization_id: &str,
    actor_principal_id: &str,
    target_principal_id: &str,
    role_id: &str,
) -> Result<OrganizationRoleBinding> {
    let mut transaction = pool.begin().await?;
    let context = lock_organization_manager_context(
        &mut transaction,
        organization_id,
        actor_principal_id,
        target_principal_id,
    )
    .await?;
    let target_membership = context
        .target_membership
        .ok_or_else(|| anyhow::anyhow!("organization_target_membership_not_found"))?;
    if target_membership.status != MEMBERSHIP_STATUS_ACTIVE
        || !context.target.active
        || context.target_user_active == Some(false)
    {
        anyhow::bail!("organization_target_membership_not_active");
    }

    let role = sqlx::query("SELECT assignable_to, scope FROM roles WHERE id = $1 FOR UPDATE")
        .bind(role_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| anyhow::anyhow!("organization_role_not_found"))?;
    let assignable_to: String = role.get("assignable_to");
    let scope: String = role.get("scope");
    if scope != ROLE_SCOPE_ORGANIZATION {
        anyhow::bail!("role_not_organization_scoped");
    }
    crate::db::ensure_role_assignable_to_principal_type(
        role_id,
        &assignable_to,
        &context.target.principal_type,
    )?;

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
    .bind(target_principal_id)
    .bind(role_id)
    .bind(Local::now().naive_utc())
    .bind(actor_principal_id)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(binding)
}

/// Removes one organization-role record under the same owner/admin boundary.
///
/// Revocation accepts suspended or removed target memberships so a manager can
/// clean up stale bindings; repeating it returns `false` without creating data.
pub async fn revoke_organization_role_as_manager(
    pool: &PgPool,
    organization_id: &str,
    actor_principal_id: &str,
    target_principal_id: &str,
    role_id: &str,
) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    let context = lock_organization_manager_context(
        &mut transaction,
        organization_id,
        actor_principal_id,
        target_principal_id,
    )
    .await?;
    context
        .target_membership
        .ok_or_else(|| anyhow::anyhow!("organization_target_membership_not_found"))?;

    let role = sqlx::query("SELECT scope FROM roles WHERE id = $1 FOR UPDATE")
        .bind(role_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| anyhow::anyhow!("organization_role_not_found"))?;
    let scope: String = role.get("scope");
    if scope != ROLE_SCOPE_ORGANIZATION {
        anyhow::bail!("role_not_organization_scoped");
    }

    let result = sqlx::query(
        r#"
        DELETE FROM organization_role_bindings
        WHERE organization_id = $1 AND principal_id = $2 AND role_id = $3
        "#,
    )
    .bind(organization_id)
    .bind(target_principal_id)
    .bind(role_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(result.rows_affected() > 0)
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
    let existing_user = sqlx::query("SELECT user_class FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(existing_user) = existing_user else {
        transaction.commit().await?;
        return Ok(None);
    };
    let existing_user_class: String = existing_user.get("user_class");
    if existing_user_class == USER_CLASS_EXTERNAL_CUSTOMER {
        let has_platform_role = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM user_roles ur
                INNER JOIN roles r ON r.id = ur.role_id
                WHERE ur.user_id = $1 AND r.scope = 'platform'
            ) OR EXISTS (
                SELECT 1
                FROM principals p
                INNER JOIN principal_roles pr ON pr.principal_id = p.id
                INNER JOIN roles r ON r.id = pr.role_id
                WHERE p.principal_type = 'user'
                  AND p.ref_id = $1
                  AND r.scope = 'platform'
            )
            "#,
        )
        .bind(user_id)
        .fetch_one(&mut *transaction)
        .await?;
        if has_platform_role {
            anyhow::bail!("cannot_promote_user_with_existing_platform_roles");
        }
    }
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
            (organization_id, principal_id, status, joined_at, invited_by, management_role, updated_at)
        VALUES ('org-internal', $1, 'active', $2, $3, $4, $2)
        ON CONFLICT (organization_id, principal_id) DO UPDATE
        SET status = 'active',
            management_role = EXCLUDED.management_role,
            invited_by = EXCLUDED.invited_by,
            updated_at = EXCLUDED.updated_at
        "#,
    )
    .bind(&principal.id)
    .bind(Local::now().naive_utc())
    .bind(actor)
    .bind(ORGANIZATION_MANAGEMENT_ROLE_OWNER)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organization_status_transitions_are_explicit() {
        assert!(is_valid_organization_status_transition(
            "active", "disabled"
        ));
        assert!(is_valid_organization_status_transition(
            "disabled", "archived"
        ));
        assert!(is_valid_organization_status_transition(
            "archived", "active"
        ));
        assert!(is_valid_organization_status_transition("active", "active"));
        assert!(!is_valid_organization_status_transition(
            "archived", "disabled"
        ));
        assert!(!is_valid_organization_status_transition(
            "unknown", "active"
        ));
    }
}

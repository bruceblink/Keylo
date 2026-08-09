use anyhow::Result;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{
    IdentitySource, LinkedOidcIdentitySource, OidcIdentitySourceLink,
    IDENTITY_SOURCE_ORGANIZATION_STRATEGY_FIXED, IDENTITY_SOURCE_ORGANIZATION_STRATEGY_NONE,
    IDENTITY_SOURCE_USER_CLASS_EXTERNAL_CUSTOMER, IDENTITY_SOURCE_USER_CLASS_INTERNAL_EMPLOYEE,
};

pub struct CreateIdentitySourceParams<'a> {
    pub name: &'a str,
    pub source_type: &'a str,
    pub display_name: &'a str,
    pub description: Option<&'a str>,
    pub config: &'a Value,
    pub claim_mapping: &'a Value,
    pub jit_enabled: bool,
    pub auto_link_enabled: bool,
    pub active: bool,
    pub allowed_user_class: &'a str,
    pub organization_strategy: &'a str,
    pub organization_id: Option<&'a str>,
}

pub struct UpdateIdentitySourceParams<'a> {
    pub id: &'a str,
    pub display_name: Option<&'a str>,
    pub description: Option<&'a str>,
    pub config: Option<&'a Value>,
    pub claim_mapping: Option<&'a Value>,
    pub jit_enabled: Option<bool>,
    pub auto_link_enabled: Option<bool>,
    pub active: Option<bool>,
    pub allowed_user_class: Option<&'a str>,
    pub organization_strategy: Option<&'a str>,
    pub organization_id: Option<&'a str>,
}

/// Enforce the closed user-class and organization-strategy combinations.
fn validate_policy_values(
    allowed_user_class: &str,
    organization_strategy: &str,
    organization_id: Option<&str>,
) -> Result<()> {
    if !matches!(
        allowed_user_class,
        IDENTITY_SOURCE_USER_CLASS_EXTERNAL_CUSTOMER | IDENTITY_SOURCE_USER_CLASS_INTERNAL_EMPLOYEE
    ) {
        anyhow::bail!("identity_source_allowed_user_class_invalid");
    }
    match organization_strategy {
        IDENTITY_SOURCE_ORGANIZATION_STRATEGY_NONE if organization_id.is_none() => Ok(()),
        IDENTITY_SOURCE_ORGANIZATION_STRATEGY_FIXED if organization_id.is_some() => Ok(()),
        _ => anyhow::bail!("identity_source_organization_policy_invalid"),
    }
}

/// Validate a fixed source against a live organization before persisting policy.
async fn validate_fixed_organization(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    allowed_user_class: &str,
    organization_strategy: &str,
    organization_id: Option<&str>,
) -> Result<()> {
    validate_policy_values(allowed_user_class, organization_strategy, organization_id)?;
    let Some(organization_id) = organization_id else {
        return Ok(());
    };
    let row = sqlx::query("SELECT kind, status FROM organizations WHERE id = $1 FOR UPDATE")
        .bind(organization_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| anyhow::anyhow!("identity_source_organization_not_found"))?;
    let kind: String = sqlx::Row::get(&row, "kind");
    let status: String = sqlx::Row::get(&row, "status");
    if status != "active" {
        anyhow::bail!("identity_source_organization_not_active");
    }
    if allowed_user_class == IDENTITY_SOURCE_USER_CLASS_EXTERNAL_CUSTOMER && kind != "customer" {
        anyhow::bail!("identity_source_external_customer_requires_customer_organization");
    }
    if allowed_user_class == IDENTITY_SOURCE_USER_CLASS_INTERNAL_EMPLOYEE && kind != "internal" {
        anyhow::bail!("identity_source_internal_employee_requires_internal_organization");
    }
    Ok(())
}

pub async fn create_identity_source(
    pool: &PgPool,
    params: CreateIdentitySourceParams<'_>,
) -> Result<IdentitySource> {
    let id = Uuid::new_v4().to_string();
    let mut transaction = pool.begin().await?;
    validate_fixed_organization(
        &mut transaction,
        params.allowed_user_class,
        params.organization_strategy,
        params.organization_id,
    )
    .await?;

    let source = sqlx::query_as::<_, IdentitySource>(
        r#"
        INSERT INTO identity_sources (
            id, name, source_type, display_name, description, config, claim_mapping,
            jit_enabled, auto_link_enabled, active, allowed_user_class,
            organization_strategy, organization_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING id, name, source_type, display_name, description, config, claim_mapping,
                  jit_enabled, auto_link_enabled, active, allowed_user_class,
                  organization_strategy, organization_id, created_at, updated_at
        "#,
    )
    .bind(id)
    .bind(params.name)
    .bind(params.source_type)
    .bind(params.display_name)
    .bind(params.description)
    .bind(params.config)
    .bind(params.claim_mapping)
    .bind(params.jit_enabled)
    .bind(params.auto_link_enabled)
    .bind(params.active)
    .bind(params.allowed_user_class)
    .bind(params.organization_strategy)
    .bind(params.organization_id)
    .fetch_one(&mut *transaction)
    .await?;

    transaction.commit().await?;

    Ok(source)
}

pub async fn list_identity_sources(pool: &PgPool) -> Result<Vec<IdentitySource>> {
    let sources = sqlx::query_as::<_, IdentitySource>(
        r#"
        SELECT id, name, source_type, display_name, description, config, claim_mapping,
               jit_enabled, auto_link_enabled, active, allowed_user_class,
               organization_strategy, organization_id, created_at, updated_at
        FROM identity_sources
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(sources)
}

pub async fn get_identity_source(pool: &PgPool, id: &str) -> Result<Option<IdentitySource>> {
    let source = sqlx::query_as::<_, IdentitySource>(
        r#"
        SELECT id, name, source_type, display_name, description, config, claim_mapping,
               jit_enabled, auto_link_enabled, active, allowed_user_class,
               organization_strategy, organization_id, created_at, updated_at
        FROM identity_sources
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(source)
}

/// Find an active identity source by its stable public name.
pub async fn get_active_identity_source_by_name(
    pool: &PgPool,
    name: &str,
) -> Result<Option<IdentitySource>> {
    Ok(sqlx::query_as::<_, IdentitySource>(
        "SELECT id, name, source_type, display_name, description, config, claim_mapping, jit_enabled, auto_link_enabled, active, allowed_user_class, organization_strategy, organization_id, created_at, updated_at FROM identity_sources WHERE name = $1 AND active = TRUE",
    )
    .bind(name)
    .fetch_optional(pool)
    .await?)
}

/// List only the upstream OIDC sources associated with a user, without exposing credentials.
pub async fn list_linked_oidc_identity_sources(
    pool: &PgPool,
    user_id: &str,
) -> Result<Vec<LinkedOidcIdentitySource>> {
    Ok(sqlx::query_as::<_, LinkedOidcIdentitySource>(
        r#"
        SELECT source.id AS source_id, source.name, source.display_name, mapping.created_at AS linked_at
        FROM external_user_mappings AS mapping
        INNER JOIN identity_sources AS source
            ON mapping.provider = CONCAT('oidc_upstream:', source.id)
        WHERE mapping.user_id = $1 AND source.source_type = 'oidc_upstream'
        ORDER BY mapping.created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?)
}

/// List local users linked to one upstream source without returning external subject values.
pub async fn list_oidc_identity_source_links(
    pool: &PgPool,
    source_id: &str,
) -> Result<Vec<OidcIdentitySourceLink>> {
    Ok(sqlx::query_as::<_, OidcIdentitySourceLink>(
        r#"
        SELECT user_record.id AS user_id,
               user_record.username,
               user_record.email,
               mapping.created_at AS linked_at
        FROM external_user_mappings AS mapping
        INNER JOIN users AS user_record ON user_record.id = mapping.user_id
        WHERE mapping.provider = CONCAT('oidc_upstream:', $1)
        ORDER BY mapping.created_at DESC, user_record.id
        "#,
    )
    .bind(source_id)
    .fetch_all(pool)
    .await?)
}

/// Update one source and atomically invalidate OIDC state when its trust boundary changes.
///
/// The actor is recorded with the security event, so a failed audit write rolls back the
/// configuration update rather than leaving changed trust settings without an audit trail.
pub async fn update_identity_source(
    pool: &PgPool,
    params: UpdateIdentitySourceParams<'_>,
    actor: Option<&str>,
) -> Result<Option<IdentitySource>> {
    let mut transaction = pool.begin().await?;
    let previous = sqlx::query_as::<_, IdentitySource>(
        r#"
        SELECT id, name, source_type, display_name, description, config, claim_mapping,
               jit_enabled, auto_link_enabled, active, allowed_user_class,
               organization_strategy, organization_id, created_at, updated_at
        FROM identity_sources
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(params.id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(previous) = previous else {
        transaction.commit().await?;
        return Ok(None);
    };
    let new_allowed_user_class = params
        .allowed_user_class
        .unwrap_or(&previous.allowed_user_class);
    let new_organization_strategy = params
        .organization_strategy
        .unwrap_or(&previous.organization_strategy);
    let new_organization_id =
        if new_organization_strategy == IDENTITY_SOURCE_ORGANIZATION_STRATEGY_NONE {
            None
        } else {
            params
                .organization_id
                .or(previous.organization_id.as_deref())
        };
    validate_fixed_organization(
        &mut transaction,
        new_allowed_user_class,
        new_organization_strategy,
        new_organization_id,
    )
    .await?;
    let source = sqlx::query_as::<_, IdentitySource>(
        r#"
        UPDATE identity_sources
        SET display_name = COALESCE($2, display_name),
            description = COALESCE($3, description),
            config = COALESCE($4, config),
            claim_mapping = COALESCE($5, claim_mapping),
            jit_enabled = COALESCE($6, jit_enabled),
            auto_link_enabled = COALESCE($7, auto_link_enabled),
            active = COALESCE($8, active),
            allowed_user_class = $9,
            organization_strategy = $10,
            organization_id = $11,
            updated_at = NOW()
        WHERE id = $1
        RETURNING id, name, source_type, display_name, description, config, claim_mapping,
                  jit_enabled, auto_link_enabled, active, allowed_user_class,
                  organization_strategy, organization_id, created_at, updated_at
        "#,
    )
    .bind(params.id)
    .bind(params.display_name)
    .bind(params.description)
    .bind(params.config)
    .bind(params.claim_mapping)
    .bind(params.jit_enabled)
    .bind(params.auto_link_enabled)
    .bind(params.active)
    .bind(new_allowed_user_class)
    .bind(new_organization_strategy)
    .bind(new_organization_id)
    .fetch_one(&mut *transaction)
    .await?;

    let source_reconfigured = previous.active
        && source.active
        && previous.source_type == "oidc_upstream"
        && (previous.config != source.config
            || previous.claim_mapping != source.claim_mapping
            || previous.allowed_user_class != source.allowed_user_class
            || previous.organization_strategy != source.organization_strategy
            || previous.organization_id != source.organization_id);
    let source_disabled =
        previous.active && !source.active && previous.source_type == "oidc_upstream";
    if source_disabled || source_reconfigured {
        let (revoke_reason, audit_event) = if source_disabled {
            ("identity_source_disabled", "identity_source.disabled")
        } else {
            (
                "identity_source_reconfigured",
                "identity_source.reconfigured",
            )
        };
        let provider = format!("oidc_upstream:{}", source.id);
        let revoked_sessions = sqlx::query(
            "UPDATE refresh_sessions
             SET revoked_at = COALESCE(revoked_at, NOW()),
                 revoke_reason = COALESCE(revoke_reason, $2)
             WHERE client_id = $1 AND revoked_at IS NULL",
        )
        .bind(&provider)
        .bind(revoke_reason)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let invalidated_authorizations = sqlx::query(
            "DELETE FROM oidc_upstream_authorizations WHERE source_id = $1 AND consumed_at IS NULL",
        )
        .bind(&source.id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        sqlx::query(
            "INSERT INTO audit_logs (id, event_type, actor, detail) VALUES ($1, $2, $3, $4)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(audit_event)
        .bind(actor)
        .bind(format!(
            "source_id={}; revoked_sessions={}; invalidated_authorizations={}",
            source.id, revoked_sessions, invalidated_authorizations
        ))
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;

    Ok(Some(source))
}

/// Create the active membership explicitly authorized by a fixed identity-source policy.
pub async fn ensure_identity_source_membership(
    pool: &PgPool,
    source: &IdentitySource,
    user_id: &str,
) -> Result<()> {
    let Some(organization_id) = source.organization_id.as_deref() else {
        return Ok(());
    };
    let principal = crate::db::ensure_user_principal(pool, user_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("identity_source_user_principal_not_found"))?;
    if crate::db::get_organization_membership(pool, organization_id, &principal.id)
        .await?
        .is_some()
    {
        return Ok(());
    }
    crate::db::upsert_organization_membership(
        pool,
        organization_id,
        &principal.id,
        "active",
        Some(&format!("identity_source:{}", source.id)),
        None,
    )
    .await?;
    Ok(())
}

/// Return a fixed source's organization only when the user's membership is live.
pub async fn identity_source_login_organization(
    pool: &PgPool,
    source: &IdentitySource,
    user_id: &str,
) -> Result<Option<String>> {
    let Some(organization_id) = source.organization_id.as_deref() else {
        return Ok(None);
    };
    let principal = crate::db::ensure_user_principal(pool, user_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("identity_source_user_principal_not_found"))?;
    Ok(
        crate::db::get_active_organization_membership(pool, organization_id, &principal.id)
            .await?
            .map(|membership| membership.organization_id),
    )
}

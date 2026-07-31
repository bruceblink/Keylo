use anyhow::Result;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{IdentitySource, LinkedOidcIdentitySource, OidcIdentitySourceLink};

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
}

pub async fn create_identity_source(
    pool: &PgPool,
    params: CreateIdentitySourceParams<'_>,
) -> Result<IdentitySource> {
    let id = Uuid::new_v4().to_string();

    let source = sqlx::query_as::<_, IdentitySource>(
        r#"
        INSERT INTO identity_sources (
            id, name, source_type, display_name, description, config, claim_mapping,
            jit_enabled, auto_link_enabled, active
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id, name, source_type, display_name, description, config, claim_mapping,
                  jit_enabled, auto_link_enabled, active, created_at, updated_at
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
    .fetch_one(pool)
    .await?;

    Ok(source)
}

pub async fn list_identity_sources(pool: &PgPool) -> Result<Vec<IdentitySource>> {
    let sources = sqlx::query_as::<_, IdentitySource>(
        r#"
        SELECT id, name, source_type, display_name, description, config, claim_mapping,
               jit_enabled, auto_link_enabled, active, created_at, updated_at
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
               jit_enabled, auto_link_enabled, active, created_at, updated_at
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
        "SELECT id, name, source_type, display_name, description, config, claim_mapping, jit_enabled, auto_link_enabled, active, created_at, updated_at FROM identity_sources WHERE name = $1 AND active = TRUE",
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
               jit_enabled, auto_link_enabled, active, created_at, updated_at
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
            updated_at = NOW()
        WHERE id = $1
        RETURNING id, name, source_type, display_name, description, config, claim_mapping,
                  jit_enabled, auto_link_enabled, active, created_at, updated_at
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
    .fetch_one(&mut *transaction)
    .await?;

    let source_reconfigured = previous.active
        && source.active
        && previous.source_type == "oidc_upstream"
        && previous.config != source.config;
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

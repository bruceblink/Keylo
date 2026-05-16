use anyhow::Result;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::IdentitySource;

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

pub async fn update_identity_source(
    pool: &PgPool,
    params: UpdateIdentitySourceParams<'_>,
) -> Result<Option<IdentitySource>> {
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
    .fetch_optional(pool)
    .await?;

    Ok(source)
}

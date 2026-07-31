use anyhow::Result;
use sqlx::{PgPool, Row};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use crate::models::{Permission, Resource, ResourceTreeNode};

pub struct CreateResourceParams<'a> {
    pub app: &'a str,
    pub resource_type: &'a str,
    pub code: &'a str,
    pub name: &'a str,
    pub parent_id: Option<&'a str>,
    pub display_order: i32,
    pub description: Option<&'a str>,
    pub metadata: Option<&'a serde_json::Value>,
    pub permission_ids: &'a [String],
}

pub struct UpdateResourceParams<'a> {
    pub name: Option<&'a str>,
    pub display_order: Option<i32>,
    pub description: Option<&'a str>,
    pub metadata: Option<&'a serde_json::Value>,
    pub active: Option<bool>,
    pub expected_version: i64,
}

fn select_resource_sql() -> &'static str {
    "SELECT id, app, resource_type, code, name, parent_id, display_order, description, metadata, active, version, created_at, updated_at FROM resources"
}

pub async fn create_resource(pool: &PgPool, params: CreateResourceParams<'_>) -> Result<Resource> {
    let resource = sqlx::query_as::<_, Resource>(
        r#"
        INSERT INTO resources
            (id, app, resource_type, code, name, parent_id, display_order, description, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (app, resource_type, code) DO UPDATE
        SET name = EXCLUDED.name,
            parent_id = EXCLUDED.parent_id,
            display_order = EXCLUDED.display_order,
            description = EXCLUDED.description,
            metadata = EXCLUDED.metadata,
            active = TRUE,
            version = resources.version + 1,
            updated_at = NOW()
        RETURNING id, app, resource_type, code, name, parent_id, display_order, description, metadata,
                  active, version, created_at, updated_at
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(params.app)
    .bind(params.resource_type)
    .bind(params.code)
    .bind(params.name)
    .bind(params.parent_id)
    .bind(params.display_order)
    .bind(params.description)
    .bind(params.metadata.cloned())
    .fetch_one(pool)
    .await?;

    for permission_id in params.permission_ids {
        assign_permission_to_resource(pool, &resource.id, permission_id).await?;
    }

    Ok(resource)
}

/// Updates mutable resource fields only when the caller's version still matches the stored row.
pub async fn update_resource(
    pool: &PgPool,
    resource_id: &str,
    params: UpdateResourceParams<'_>,
) -> Result<Option<Resource>> {
    Ok(sqlx::query_as::<_, Resource>(
        r#"
        UPDATE resources
        SET name = COALESCE($2, name),
            display_order = COALESCE($3, display_order),
            description = COALESCE($4, description),
            metadata = COALESCE($5, metadata),
            active = COALESCE($6, active),
            version = version + 1,
            updated_at = NOW()
        WHERE id = $1 AND version = $7
        RETURNING id, app, resource_type, code, name, parent_id, display_order, description, metadata,
                  active, version, created_at, updated_at
        "#,
    )
    .bind(resource_id)
    .bind(params.name)
    .bind(params.display_order)
    .bind(params.description)
    .bind(params.metadata.cloned())
    .bind(params.active)
    .bind(params.expected_version)
    .fetch_optional(pool)
    .await?)
}

pub async fn list_resources(
    pool: &PgPool,
    app: Option<&str>,
    resource_type: Option<&str>,
    active: Option<bool>,
) -> Result<Vec<Resource>> {
    Ok(sqlx::query_as::<_, Resource>(
        r#"
        SELECT id, app, resource_type, code, name, parent_id, display_order, description, metadata,
               active, version, created_at, updated_at
        FROM resources
        WHERE ($1::text IS NULL OR app = $1)
          AND ($2::text IS NULL OR resource_type = $2)
          AND ($3::boolean IS NULL OR active = $3)
        ORDER BY app, resource_type, display_order, code
        "#,
    )
    .bind(app)
    .bind(resource_type)
    .bind(active)
    .fetch_all(pool)
    .await?)
}

pub async fn get_resource_by_id(pool: &PgPool, resource_id: &str) -> Result<Option<Resource>> {
    let sql = format!("{} WHERE id = $1", select_resource_sql());
    Ok(sqlx::query_as::<_, Resource>(&sql)
        .bind(resource_id)
        .fetch_optional(pool)
        .await?)
}

pub async fn get_resource_by_code(
    pool: &PgPool,
    app: &str,
    resource_type: &str,
    code: &str,
) -> Result<Option<Resource>> {
    let sql = format!(
        "{} WHERE app = $1 AND resource_type = $2 AND code = $3",
        select_resource_sql()
    );
    Ok(sqlx::query_as::<_, Resource>(&sql)
        .bind(app)
        .bind(resource_type)
        .bind(code)
        .fetch_optional(pool)
        .await?)
}

pub async fn assign_permission_to_resource(
    pool: &PgPool,
    resource_id: &str,
    permission_id: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO resource_permissions (resource_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(resource_id)
    .bind(permission_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Removes one explicit resource-permission binding and reports whether it existed.
pub async fn revoke_permission_from_resource(
    pool: &PgPool,
    resource_id: &str,
    permission_id: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "DELETE FROM resource_permissions WHERE resource_id = $1 AND permission_id = $2",
    )
    .bind(resource_id)
    .bind(permission_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn get_resource_permissions(pool: &PgPool, resource_id: &str) -> Result<Vec<Permission>> {
    Ok(sqlx::query_as::<_, Permission>(
        r#"
        SELECT p.id, p.name, p.description, p.version, p.created_at, p.updated_at
        FROM permissions p
        INNER JOIN resource_permissions rp ON rp.permission_id = p.id
        WHERE rp.resource_id = $1
        ORDER BY p.name
        "#,
    )
    .bind(resource_id)
    .fetch_all(pool)
    .await?)
}

pub async fn authorized_resources_for_principal(
    pool: &PgPool,
    principal_id: &str,
    app: &str,
    resource_type: &str,
) -> Result<Vec<ResourceTreeNode>> {
    let wildcard = crate::db::principal_has_wildcard_permission(pool, principal_id).await?;
    let rows = if wildcard {
        sqlx::query(
            r#"
            SELECT id, app, resource_type, code, name, parent_id, display_order, description, metadata,
                   active, version, created_at, updated_at
            FROM resources
            WHERE app = $1 AND resource_type = $2 AND active = TRUE
            ORDER BY display_order, code
            "#,
        )
        .bind(app)
        .bind(resource_type)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query(
            r#"
            WITH RECURSIVE permitted AS (
                SELECT DISTINCT r.*
                FROM resources r
                INNER JOIN resource_permissions rperm ON rperm.resource_id = r.id
                INNER JOIN role_permissions rp ON rp.permission_id = rperm.permission_id
                INNER JOIN principal_roles pr ON pr.role_id = rp.role_id
                WHERE pr.principal_id = $1
                  AND r.app = $2
                  AND r.resource_type = $3
                  AND r.active = TRUE
            ),
            visible AS (
                SELECT * FROM permitted
                UNION
                SELECT parent.*
                FROM resources parent
                INNER JOIN visible child ON child.parent_id = parent.id
                WHERE parent.active = TRUE
            )
            SELECT id, app, resource_type, code, name, parent_id, display_order, description, metadata,
                   active, version, created_at, updated_at
            FROM visible
            ORDER BY display_order, code
            "#,
        )
        .bind(principal_id)
        .bind(app)
        .bind(resource_type)
        .fetch_all(pool)
        .await?
    };

    let mut resources = Vec::with_capacity(rows.len());
    for row in rows {
        resources.push(Resource {
            id: row.get("id"),
            app: row.get("app"),
            resource_type: row.get("resource_type"),
            code: row.get("code"),
            name: row.get("name"),
            parent_id: row.get("parent_id"),
            display_order: row.get("display_order"),
            description: row.get("description"),
            metadata: row.get("metadata"),
            active: row.get("active"),
            version: row.get("version"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        });
    }

    let resource_ids = resources
        .iter()
        .map(|resource| resource.id.clone())
        .collect::<Vec<_>>();
    let permission_map = resource_permission_map(pool, &resource_ids).await?;

    Ok(build_tree(resources, permission_map))
}

async fn resource_permission_map(
    pool: &PgPool,
    resource_ids: &[String],
) -> Result<HashMap<String, Vec<Permission>>> {
    if resource_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let rows = sqlx::query(
        r#"
        SELECT rp.resource_id,
               p.id, p.name, p.description, p.version, p.created_at, p.updated_at
        FROM resource_permissions rp
        INNER JOIN permissions p ON p.id = rp.permission_id
        WHERE rp.resource_id = ANY($1)
        ORDER BY p.name
        "#,
    )
    .bind(resource_ids)
    .fetch_all(pool)
    .await?;

    let mut map: HashMap<String, Vec<Permission>> = HashMap::new();
    for row in rows {
        let resource_id: String = row.get("resource_id");
        map.entry(resource_id).or_default().push(Permission {
            id: row.get("id"),
            name: row.get("name"),
            description: row.get("description"),
            version: row.get("version"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        });
    }

    Ok(map)
}

fn build_tree(
    resources: Vec<Resource>,
    mut permission_map: HashMap<String, Vec<Permission>>,
) -> Vec<ResourceTreeNode> {
    let visible_ids = resources
        .iter()
        .map(|resource| resource.id.clone())
        .collect::<HashSet<_>>();
    let mut children_by_parent: HashMap<Option<String>, Vec<Resource>> = HashMap::new();

    for resource in resources {
        let parent = resource
            .parent_id
            .clone()
            .filter(|parent_id| visible_ids.contains(parent_id));
        children_by_parent.entry(parent).or_default().push(resource);
    }

    fn build_level(
        parent_id: Option<String>,
        children_by_parent: &mut HashMap<Option<String>, Vec<Resource>>,
        permission_map: &mut HashMap<String, Vec<Permission>>,
    ) -> Vec<ResourceTreeNode> {
        let mut children = children_by_parent.remove(&parent_id).unwrap_or_default();
        children.sort_by(|left, right| {
            left.display_order
                .cmp(&right.display_order)
                .then_with(|| left.code.cmp(&right.code))
        });

        children
            .into_iter()
            .map(|resource| {
                let resource_id = resource.id.clone();
                ResourceTreeNode {
                    permissions: permission_map.remove(&resource_id).unwrap_or_default(),
                    children: build_level(Some(resource_id), children_by_parent, permission_map),
                    resource,
                }
            })
            .collect()
    }

    build_level(None, &mut children_by_parent, &mut permission_map)
}

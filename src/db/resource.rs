use anyhow::Result;
use sqlx::{PgPool, Row};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use crate::models::{Permission, Resource, ResourceChangeHistory, ResourceTreeNode};

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
    "SELECT id, organization_id, app, resource_type, code, name, parent_id, display_order, description, metadata, active, version, created_at, updated_at FROM resources"
}

/// Creates or reactivates a platform resource for callers that use the original API.
pub async fn create_resource(pool: &PgPool, params: CreateResourceParams<'_>) -> Result<Resource> {
    create_resource_in_organization(pool, None, params).await
}

/// Creates or reactivates one resource inside an explicit tenant scope.
///
/// A missing organization keeps the historical platform-resource behavior. PostgreSQL 12 needs
/// different conflict targets for platform and tenant rows because NULL is distinct by default.
pub async fn create_resource_in_organization(
    pool: &PgPool,
    organization_id: Option<&str>,
    params: CreateResourceParams<'_>,
) -> Result<Resource> {
    let platform_sql = r#"
        INSERT INTO resources
            (id, organization_id, app, resource_type, code, name, parent_id, display_order,
             description, metadata)
        VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (app, resource_type, code) WHERE organization_id IS NULL DO UPDATE
        SET name = EXCLUDED.name,
            parent_id = EXCLUDED.parent_id,
            display_order = EXCLUDED.display_order,
            description = EXCLUDED.description,
            metadata = EXCLUDED.metadata,
            active = TRUE,
            version = resources.version + 1,
            updated_at = NOW()
        RETURNING id, organization_id, app, resource_type, code, name, parent_id, display_order,
                  description, metadata, active, version, created_at, updated_at
        "#;
    let organization_sql = r#"
        INSERT INTO resources
            (id, organization_id, app, resource_type, code, name, parent_id, display_order,
             description, metadata)
        VALUES ($1, $10, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (organization_id, app, resource_type, code)
            WHERE organization_id IS NOT NULL DO UPDATE
        SET name = EXCLUDED.name,
            parent_id = EXCLUDED.parent_id,
            display_order = EXCLUDED.display_order,
            description = EXCLUDED.description,
            metadata = EXCLUDED.metadata,
            active = TRUE,
            version = resources.version + 1,
            updated_at = NOW()
        RETURNING id, organization_id, app, resource_type, code, name, parent_id, display_order,
                  description, metadata, active, version, created_at, updated_at
        "#;
    let sql = if organization_id.is_some() {
        organization_sql
    } else {
        platform_sql
    };
    let mut query = sqlx::query_as::<_, Resource>(sql)
        .bind(Uuid::new_v4().to_string())
        .bind(params.app)
        .bind(params.resource_type)
        .bind(params.code)
        .bind(params.name)
        .bind(params.parent_id)
        .bind(params.display_order)
        .bind(params.description)
        .bind(params.metadata.cloned());
    if let Some(organization_id) = organization_id {
        query = query.bind(organization_id);
    }
    let resource = query.fetch_one(pool).await?;

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
        RETURNING id, organization_id, app, resource_type, code, name, parent_id, display_order,
                  description, metadata, active, version, created_at, updated_at
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

/// Stores immutable resource snapshots so UI/API capability changes can be inspected safely.
pub async fn create_resource_change_history(
    pool: &PgPool,
    actor: Option<&str>,
    change_reason: Option<&str>,
    before: &Resource,
    after: &Resource,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO resource_change_history
            (id, resource_id, version, actor, change_reason, before_state, after_state)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&after.id)
    .bind(after.version)
    .bind(actor)
    .bind(change_reason)
    .bind(serde_json::to_value(before)?)
    .bind(serde_json::to_value(after)?)
    .execute(pool)
    .await?;

    Ok(())
}

/// Lists resource snapshots from newest to oldest for bounded administrative inspection.
pub async fn list_resource_change_history(
    pool: &PgPool,
    resource_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<ResourceChangeHistory>> {
    Ok(sqlx::query_as::<_, ResourceChangeHistory>(
        r#"
        SELECT id, resource_id, version, actor, change_reason, before_state, after_state,
               created_at
        FROM resource_change_history
        WHERE resource_id = $1
        ORDER BY version DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(resource_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?)
}

/// Loads a recorded resource change whose before_state is the exact target for a revert.
pub async fn get_resource_change_history(
    pool: &PgPool,
    resource_id: &str,
    version: i64,
) -> Result<Option<ResourceChangeHistory>> {
    Ok(sqlx::query_as::<_, ResourceChangeHistory>(
        r#"
        SELECT id, resource_id, version, actor, change_reason, before_state, after_state,
               created_at
        FROM resource_change_history
        WHERE resource_id = $1 AND version = $2
        "#,
    )
    .bind(resource_id)
    .bind(version)
    .fetch_optional(pool)
    .await?)
}

/// Restores mutable resource fields exactly, including nullable values, when the version matches.
pub async fn restore_resource(
    pool: &PgPool,
    resource_id: &str,
    target: &Resource,
    expected_version: i64,
) -> Result<Option<Resource>> {
    Ok(sqlx::query_as::<_, Resource>(
        r#"
        UPDATE resources
        SET name = $2,
            display_order = $3,
            description = $4,
            metadata = $5,
            active = $6,
            version = version + 1,
            updated_at = NOW()
        WHERE id = $1 AND version = $7
        RETURNING id, organization_id, app, resource_type, code, name, parent_id, display_order,
                  description, metadata, active, version, created_at, updated_at
        "#,
    )
    .bind(resource_id)
    .bind(&target.name)
    .bind(target.display_order)
    .bind(&target.description)
    .bind(&target.metadata)
    .bind(target.active)
    .bind(expected_version)
    .fetch_optional(pool)
    .await?)
}

pub async fn list_resources(
    pool: &PgPool,
    app: Option<&str>,
    resource_type: Option<&str>,
    active: Option<bool>,
) -> Result<Vec<Resource>> {
    list_resources_for_admin(pool, None, app, resource_type, active).await
}

/// Lists administrative resources with an optional exact tenant filter.
///
/// `None` intentionally means no organization filter so existing list clients still see the same
/// result set. Supplying an ID selects that tenant only.
pub async fn list_resources_for_admin(
    pool: &PgPool,
    organization_id: Option<&str>,
    app: Option<&str>,
    resource_type: Option<&str>,
    active: Option<bool>,
) -> Result<Vec<Resource>> {
    Ok(sqlx::query_as::<_, Resource>(
        r#"
        SELECT id, organization_id, app, resource_type, code, name, parent_id, display_order,
               description, metadata, active, version, created_at, updated_at
        FROM resources
        WHERE ($1::text IS NULL OR organization_id = $1)
          AND ($2::text IS NULL OR app = $2)
          AND ($3::text IS NULL OR resource_type = $3)
          AND ($4::boolean IS NULL OR active = $4)
        ORDER BY organization_id NULLS FIRST, app, resource_type, display_order, code
        "#,
    )
    .bind(organization_id)
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
    get_resource_by_code_in_organization(pool, None, app, resource_type, code).await
}

/// Resolves a resource identity inside exactly one platform or tenant scope.
pub async fn get_resource_by_code_in_organization(
    pool: &PgPool,
    organization_id: Option<&str>,
    app: &str,
    resource_type: &str,
    code: &str,
) -> Result<Option<Resource>> {
    let sql = format!(
        "{} WHERE app = $1 AND resource_type = $2 AND code = $3 AND organization_id IS NOT DISTINCT FROM $4",
        select_resource_sql()
    );
    Ok(sqlx::query_as::<_, Resource>(&sql)
        .bind(app)
        .bind(resource_type)
        .bind(code)
        .bind(organization_id)
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
    authorized_resources_for_principal_in_organization(pool, principal_id, None, app, resource_type)
        .await
}

/// Builds a resource tree from roles that are valid in exactly one authorization scope.
///
/// Platform and tenant role sources stay separate: an internal wildcard does not silently grant
/// access to customer resources, while tenant roles require a currently active organization and
/// membership on every read.
pub async fn authorized_resources_for_principal_in_organization(
    pool: &PgPool,
    principal_id: &str,
    organization_id: Option<&str>,
    app: &str,
    resource_type: &str,
) -> Result<Vec<ResourceTreeNode>> {
    let wildcard =
        principal_has_wildcard_in_organization(pool, principal_id, organization_id).await?;
    let rows = if wildcard {
        sqlx::query_as::<_, Resource>(
            r#"
            SELECT id, organization_id, app, resource_type, code, name, parent_id, display_order,
                   description, metadata, active, version, created_at, updated_at
            FROM resources
            WHERE app = $1
              AND resource_type = $2
              AND organization_id IS NOT DISTINCT FROM $3
              AND active = TRUE
            ORDER BY display_order, code
            "#,
        )
        .bind(app)
        .bind(resource_type)
        .bind(organization_id)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, Resource>(
            r#"
            WITH RECURSIVE effective_roles AS (
                SELECT pr.role_id
                FROM principal_roles pr
                INNER JOIN roles role ON role.id = pr.role_id
                INNER JOIN principals principal ON principal.id = pr.principal_id
                LEFT JOIN users u
                    ON principal.principal_type = 'user' AND u.id = principal.ref_id
                WHERE $4::text IS NULL
                  AND pr.principal_id = $1
                  AND role.scope = 'platform'
                  AND (principal.principal_type <> 'user' OR u.user_class = 'internal_employee')

                UNION ALL

                SELECT binding.role_id
                FROM organization_role_bindings binding
                INNER JOIN roles role
                    ON role.id = binding.role_id AND role.scope = 'organization'
                INNER JOIN principals principal ON principal.id = binding.principal_id
                LEFT JOIN users user_account
                    ON principal.principal_type = 'user' AND user_account.id = principal.ref_id
                INNER JOIN organization_memberships membership
                    ON membership.organization_id = binding.organization_id
                   AND membership.principal_id = binding.principal_id
                   AND membership.status = 'active'
                INNER JOIN organizations organization
                    ON organization.id = binding.organization_id
                   AND organization.status = 'active'
                WHERE $4::text IS NOT NULL
                  AND binding.organization_id = $4
                  AND binding.principal_id = $1
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
            ),
            permitted AS (
                SELECT DISTINCT r.*
                FROM resources r
                INNER JOIN resource_permissions rperm ON rperm.resource_id = r.id
                INNER JOIN role_permissions rp ON rp.permission_id = rperm.permission_id
                INNER JOIN effective_roles role ON role.role_id = rp.role_id
                WHERE r.app = $2
                  AND r.resource_type = $3
                  AND r.organization_id IS NOT DISTINCT FROM $4
                  AND r.active = TRUE
            ),
            visible AS (
                SELECT * FROM permitted
                UNION
                SELECT parent.*
                FROM resources parent
                INNER JOIN visible child ON child.parent_id = parent.id
                WHERE parent.organization_id IS NOT DISTINCT FROM $4
                  AND parent.active = TRUE
            )
            SELECT id, organization_id, app, resource_type, code, name, parent_id, display_order,
                   description, metadata, active, version, created_at, updated_at
            FROM visible
            ORDER BY display_order, code
            "#,
        )
        .bind(principal_id)
        .bind(app)
        .bind(resource_type)
        .bind(organization_id)
        .fetch_all(pool)
        .await?
    };

    let resource_ids = rows
        .iter()
        .map(|resource| resource.id.clone())
        .collect::<Vec<_>>();
    let permission_map = resource_permission_map(pool, &resource_ids).await?;

    Ok(build_tree(rows, permission_map))
}

/// Resolves wildcard access from only the role table that belongs to the requested scope.
async fn principal_has_wildcard_in_organization(
    pool: &PgPool,
    principal_id: &str,
    organization_id: Option<&str>,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM principal_roles pr
            INNER JOIN roles role ON role.id = pr.role_id
            INNER JOIN principals principal ON principal.id = pr.principal_id
            LEFT JOIN users u
                ON principal.principal_type = 'user' AND u.id = principal.ref_id
            INNER JOIN role_permissions rp ON rp.role_id = pr.role_id
            INNER JOIN permissions permission ON permission.id = rp.permission_id
            WHERE $2::text IS NULL
              AND pr.principal_id = $1
              AND role.scope = 'platform'
              AND (principal.principal_type <> 'user' OR u.user_class = 'internal_employee')
              AND permission.name = '*:*:*'

            UNION ALL

            SELECT 1
            FROM organization_role_bindings binding
            INNER JOIN roles role
                ON role.id = binding.role_id AND role.scope = 'organization'
            INNER JOIN principals principal ON principal.id = binding.principal_id
            LEFT JOIN users user_account
                ON principal.principal_type = 'user' AND user_account.id = principal.ref_id
            INNER JOIN organization_memberships membership
                ON membership.organization_id = binding.organization_id
               AND membership.principal_id = binding.principal_id
               AND membership.status = 'active'
            INNER JOIN organizations organization
                ON organization.id = binding.organization_id
               AND organization.status = 'active'
            INNER JOIN role_permissions rp ON rp.role_id = binding.role_id
            INNER JOIN permissions permission ON permission.id = rp.permission_id
            WHERE $2::text IS NOT NULL
              AND binding.organization_id = $2
              AND binding.principal_id = $1
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
              AND permission.name = '*:*:*'
        )
        "#,
    )
    .bind(principal_id)
    .bind(organization_id)
    .fetch_one(pool)
    .await?)
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

use anyhow::Result;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::models::*;

pub fn valid_role_assignable_to(assignable_to: &str) -> bool {
    matches!(
        assignable_to,
        "user" | "service" | "device" | "client" | "all"
    )
}

pub fn ensure_role_assignable_to_principal_type(
    role_id: &str,
    assignable_to: &str,
    principal_type: &str,
) -> Result<()> {
    if !valid_role_assignable_to(assignable_to) {
        anyhow::bail!("invalid_role_assignable_to: role={}", role_id);
    }

    if assignable_to != "all" && assignable_to != principal_type {
        anyhow::bail!(
            "role_not_assignable_to_principal_type: role={}, principal_type={}",
            role_id,
            principal_type
        );
    }

    Ok(())
}

/// Validates the platform-only storage used by `user_roles` and `principal_roles`.
/// Organization roles deliberately use `organization_role_bindings` so they never
/// become global permissions by accident.
pub fn ensure_platform_role_assignment(
    role_id: &str,
    assignable_to: &str,
    scope: &str,
    principal_type: &str,
) -> Result<()> {
    if scope != ROLE_SCOPE_PLATFORM {
        anyhow::bail!(
            "organization_role_requires_organization_binding: role={}",
            role_id
        );
    }

    ensure_role_assignable_to_principal_type(role_id, assignable_to, principal_type)
}

/// Prevents customer accounts from receiving platform-wide permissions.
/// Human organization roles are intentionally assigned through memberships instead.
pub fn ensure_user_can_receive_platform_role(
    role_id: &str,
    assignable_to: &str,
    scope: &str,
    user_class: &str,
) -> Result<()> {
    ensure_platform_role_assignment(role_id, assignable_to, scope, "user")?;

    if user_class != USER_CLASS_INTERNAL_EMPLOYEE {
        anyhow::bail!(
            "external_customer_cannot_receive_platform_role: role={}",
            role_id
        );
    }

    Ok(())
}

async fn ensure_role_assignable_to_update_is_compatible(
    pool: &PgPool,
    role_id: &str,
    assignable_to: &str,
) -> Result<()> {
    if assignable_to == "all" {
        return Ok(());
    }

    if assignable_to != "user" {
        let user_role = sqlx::query("SELECT 1 FROM user_roles WHERE role_id = $1 LIMIT 1")
            .bind(role_id)
            .fetch_optional(pool)
            .await?;
        if user_role.is_some() {
            anyhow::bail!(
                "role_assignable_to_conflicts_with_existing_assignments: role={}, assignable_to={}, existing_principal_type=user",
                role_id,
                assignable_to
            );
        }
    }

    let conflicting_principal = sqlx::query(
        r#"
        SELECT p.principal_type
        FROM principal_roles pr
        INNER JOIN principals p ON p.id = pr.principal_id
        WHERE pr.role_id = $1 AND p.principal_type <> $2
        LIMIT 1
        "#,
    )
    .bind(role_id)
    .bind(assignable_to)
    .fetch_optional(pool)
    .await?;

    if let Some(row) = conflicting_principal {
        let principal_type: String = row.get("principal_type");
        anyhow::bail!(
            "role_assignable_to_conflicts_with_existing_assignments: role={}, assignable_to={}, existing_principal_type={}",
            role_id,
            assignable_to,
            principal_type
        );
    }

    Ok(())
}

/// 角色相关数据库操作
/// 创建角色
pub async fn create_role(pool: &PgPool, name: &str, description: Option<&str>) -> Result<Role> {
    create_role_with_options(pool, name, description, "all", false).await
}

pub async fn create_role_with_options(
    pool: &PgPool,
    name: &str,
    description: Option<&str>,
    assignable_to: &str,
    system: bool,
) -> Result<Role> {
    create_role_with_scope(
        pool,
        name,
        description,
        assignable_to,
        system,
        ROLE_SCOPE_PLATFORM,
    )
    .await
}

/// Creates an organization-only role. Its scope is immutable through the
/// existing platform role update API so a tenant role cannot become global.
pub async fn create_organization_role(
    pool: &PgPool,
    name: &str,
    description: Option<&str>,
    assignable_to: &str,
) -> Result<Role> {
    create_role_with_scope(
        pool,
        name,
        description,
        assignable_to,
        false,
        ROLE_SCOPE_ORGANIZATION,
    )
    .await
}

/// Inserts a role with an immutable scope chosen by the caller-facing wrapper.
async fn create_role_with_scope(
    pool: &PgPool,
    name: &str,
    description: Option<&str>,
    assignable_to: &str,
    system: bool,
    scope: &str,
) -> Result<Role> {
    if !valid_role_assignable_to(assignable_to) {
        anyhow::bail!("invalid_assignable_to");
    }
    if !matches!(scope, ROLE_SCOPE_PLATFORM | ROLE_SCOPE_ORGANIZATION) {
        anyhow::bail!("invalid_role_scope");
    }

    let id = Uuid::new_v4().to_string();
    let now = chrono::Local::now().naive_utc();

    let role = sqlx::query_as::<_, Role>(
        r#"
        INSERT INTO roles (id, name, description, assignable_to, system, scope, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id, name, description, assignable_to, system, version, created_at, updated_at
        "#,
    )
    .bind(&id)
    .bind(name)
    .bind(description)
    .bind(assignable_to)
    .bind(system)
    .bind(scope)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(role)
}

/// 获取所有角色
pub async fn get_all_roles(pool: &PgPool) -> Result<Vec<Role>> {
    let roles = sqlx::query_as::<_, Role>(
        "SELECT id, name, description, assignable_to, system, version, created_at, updated_at FROM roles ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    Ok(roles)
}

/// 根据ID获取角色
pub async fn get_role_by_id(pool: &PgPool, role_id: &str) -> Result<Option<Role>> {
    let role = sqlx::query_as::<_, Role>(
        "SELECT id, name, description, assignable_to, system, version, created_at, updated_at FROM roles WHERE id = $1",
    )
    .bind(role_id)
    .fetch_optional(pool)
    .await?;

    Ok(role)
}

/// 根据名称获取角色
pub async fn get_role_by_name(pool: &PgPool, name: &str) -> Result<Option<Role>> {
    let role = sqlx::query_as::<_, Role>(
        "SELECT id, name, description, assignable_to, system, version, created_at, updated_at FROM roles WHERE name = $1",
    )
    .bind(name)
    .fetch_optional(pool)
    .await?;

    Ok(role)
}

/// 更新角色
pub async fn update_role(
    pool: &PgPool,
    role_id: &str,
    name: Option<&str>,
    description: Option<&str>,
    assignable_to: Option<&str>,
    system: Option<bool>,
    expected_version: Option<i64>,
) -> Result<Option<Role>> {
    if let Some(assignable_to) = assignable_to {
        if !valid_role_assignable_to(assignable_to) {
            anyhow::bail!("invalid_assignable_to");
        }
        ensure_role_assignable_to_update_is_compatible(pool, role_id, assignable_to).await?;
    }

    let now = chrono::Local::now().naive_utc();

    let role = sqlx::query_as::<_, Role>(
        r#"
        UPDATE roles
        SET name = COALESCE($2, name),
            description = COALESCE($3, description),
            assignable_to = COALESCE($4, assignable_to),
            system = COALESCE($5, system),
            version = version + 1,
            updated_at = $6
        WHERE id = $1 AND ($7::BIGINT IS NULL OR version = $7)
        RETURNING id, name, description, assignable_to, system, version, created_at, updated_at
        "#,
    )
    .bind(role_id)
    .bind(name)
    .bind(description)
    .bind(assignable_to)
    .bind(system)
    .bind(now)
    .bind(expected_version)
    .fetch_optional(pool)
    .await?;

    Ok(role)
}

/// Stores immutable before/after role snapshots so administrators can investigate a configuration change.
pub async fn create_role_change_history(
    pool: &PgPool,
    actor: Option<&str>,
    change_reason: Option<&str>,
    before: &Role,
    after: &Role,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO role_change_history
            (id, role_id, version, actor, change_reason, before_state, after_state)
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

/// Lists role change snapshots from newest to oldest for a bounded administrator investigation view.
pub async fn list_role_change_history(
    pool: &PgPool,
    role_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<RoleChangeHistory>> {
    Ok(sqlx::query_as::<_, RoleChangeHistory>(
        r#"
        SELECT id, role_id, version, actor, change_reason, before_state, after_state, created_at
        FROM role_change_history
        WHERE role_id = $1
        ORDER BY version DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(role_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?)
}

/// Loads one recorded role change whose before_state is the exact target for a revert operation.
pub async fn get_role_change_history(
    pool: &PgPool,
    role_id: &str,
    version: i64,
) -> Result<Option<RoleChangeHistory>> {
    Ok(sqlx::query_as::<_, RoleChangeHistory>(
        r#"
        SELECT id, role_id, version, actor, change_reason, before_state, after_state, created_at
        FROM role_change_history
        WHERE role_id = $1 AND version = $2
        "#,
    )
    .bind(role_id)
    .bind(version)
    .fetch_optional(pool)
    .await?)
}

/// Restores every mutable role field from a historical snapshot when the current version still matches.
pub async fn restore_role(
    pool: &PgPool,
    role_id: &str,
    target: &Role,
    expected_version: i64,
) -> Result<Option<Role>> {
    ensure_role_assignable_to_update_is_compatible(pool, role_id, &target.assignable_to).await?;

    Ok(sqlx::query_as::<_, Role>(
        r#"
        UPDATE roles
        SET name = $2,
            description = $3,
            assignable_to = $4,
            system = $5,
            version = version + 1,
            updated_at = NOW()
        WHERE id = $1 AND version = $6
        RETURNING id, name, description, assignable_to, system, version, created_at, updated_at
        "#,
    )
    .bind(role_id)
    .bind(&target.name)
    .bind(&target.description)
    .bind(&target.assignable_to)
    .bind(target.system)
    .bind(expected_version)
    .fetch_optional(pool)
    .await?)
}

/// 删除角色
pub async fn delete_role(pool: &PgPool, role_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM roles WHERE id = $1")
        .bind(role_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// 权限相关数据库操作
/// 创建权限
pub async fn create_permission(
    pool: &PgPool,
    name: &str,
    description: Option<&str>,
) -> Result<Permission> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Local::now().naive_utc();

    let permission = sqlx::query_as::<_, Permission>(
        r#"
        INSERT INTO permissions (id, name, description, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, name, description, version, created_at, updated_at
        "#,
    )
    .bind(&id)
    .bind(name)
    .bind(description)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(permission)
}

/// 获取所有权限
pub async fn get_all_permissions(pool: &PgPool) -> Result<Vec<Permission>> {
    let permissions = sqlx::query_as::<_, Permission>(
        "SELECT id, name, description, version, created_at, updated_at FROM permissions ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    Ok(permissions)
}

/// 按前缀获取权限
pub async fn get_permissions_by_prefix(pool: &PgPool, prefix: &str) -> Result<Vec<Permission>> {
    let pattern = format!("{}%", prefix);
    let permissions = sqlx::query_as::<_, Permission>(
        "SELECT id, name, description, version, created_at, updated_at FROM permissions WHERE name LIKE $1 ORDER BY name",
    )
    .bind(pattern)
    .fetch_all(pool)
    .await?;

    Ok(permissions)
}

/// 根据ID获取权限
pub async fn get_permission_by_id(
    pool: &PgPool,
    permission_id: &str,
) -> Result<Option<Permission>> {
    let permission = sqlx::query_as::<_, Permission>(
        "SELECT id, name, description, version, created_at, updated_at FROM permissions WHERE id = $1",
    )
    .bind(permission_id)
    .fetch_optional(pool)
    .await?;

    Ok(permission)
}

/// 根据名称获取权限
pub async fn get_permission_by_name(pool: &PgPool, name: &str) -> Result<Option<Permission>> {
    let permission = sqlx::query_as::<_, Permission>(
        "SELECT id, name, description, version, created_at, updated_at FROM permissions WHERE name = $1",
    )
    .bind(name)
    .fetch_optional(pool)
    .await?;

    Ok(permission)
}

/// 更新权限
pub async fn update_permission(
    pool: &PgPool,
    permission_id: &str,
    name: Option<&str>,
    description: Option<&str>,
    expected_version: Option<i64>,
) -> Result<Option<Permission>> {
    let now = chrono::Local::now().naive_utc();

    let permission = sqlx::query_as::<_, Permission>(
        r#"
        UPDATE permissions
        SET name = COALESCE($2, name),
            description = COALESCE($3, description),
            version = version + 1,
            updated_at = $4
        WHERE id = $1 AND ($5::BIGINT IS NULL OR version = $5)
        RETURNING id, name, description, version, created_at, updated_at
        "#,
    )
    .bind(permission_id)
    .bind(name)
    .bind(description)
    .bind(now)
    .bind(expected_version)
    .fetch_optional(pool)
    .await?;

    Ok(permission)
}

/// Stores immutable before/after permission snapshots for administrator investigations and rollback planning.
pub async fn create_permission_change_history(
    pool: &PgPool,
    actor: Option<&str>,
    change_reason: Option<&str>,
    before: &Permission,
    after: &Permission,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO permission_change_history
            (id, permission_id, version, actor, change_reason, before_state, after_state)
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

/// Lists permission snapshots from newest to oldest with bounded pagination.
pub async fn list_permission_change_history(
    pool: &PgPool,
    permission_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<PermissionChangeHistory>> {
    Ok(sqlx::query_as::<_, PermissionChangeHistory>(
        r#"
        SELECT id, permission_id, version, actor, change_reason, before_state, after_state,
               created_at
        FROM permission_change_history
        WHERE permission_id = $1
        ORDER BY version DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(permission_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?)
}

/// Loads one recorded permission change whose before_state is the exact target for a revert.
pub async fn get_permission_change_history(
    pool: &PgPool,
    permission_id: &str,
    version: i64,
) -> Result<Option<PermissionChangeHistory>> {
    Ok(sqlx::query_as::<_, PermissionChangeHistory>(
        r#"
        SELECT id, permission_id, version, actor, change_reason, before_state, after_state,
               created_at
        FROM permission_change_history
        WHERE permission_id = $1 AND version = $2
        "#,
    )
    .bind(permission_id)
    .bind(version)
    .fetch_optional(pool)
    .await?)
}

/// Restores every mutable permission field from a snapshot when the caller still has the current version.
pub async fn restore_permission(
    pool: &PgPool,
    permission_id: &str,
    target: &Permission,
    expected_version: i64,
) -> Result<Option<Permission>> {
    Ok(sqlx::query_as::<_, Permission>(
        r#"
        UPDATE permissions
        SET name = $2,
            description = $3,
            version = version + 1,
            updated_at = NOW()
        WHERE id = $1 AND version = $4
        RETURNING id, name, description, version, created_at, updated_at
        "#,
    )
    .bind(permission_id)
    .bind(&target.name)
    .bind(&target.description)
    .bind(expected_version)
    .fetch_optional(pool)
    .await?)
}

/// 删除权限
pub async fn delete_permission(pool: &PgPool, permission_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM permissions WHERE id = $1")
        .bind(permission_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// 用户角色关系操作
/// 为用户分配角色
pub async fn assign_role_to_user(pool: &PgPool, user_id: &str, role_id: &str) -> Result<()> {
    assign_roles_to_user_batch(pool, user_id, &[role_id.to_string()]).await
}

/// 为用户批量分配角色
pub async fn assign_roles_to_user_batch(
    pool: &PgPool,
    user_id: &str,
    role_ids: &[String],
) -> Result<()> {
    let principal = crate::db::ensure_user_principal(pool, user_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("user_not_found"))?;
    let mut normalized_role_ids: Vec<String> = role_ids
        .iter()
        .map(|role_id| role_id.trim().to_string())
        .filter(|role_id| !role_id.is_empty())
        .collect();
    normalized_role_ids.sort();
    normalized_role_ids.dedup();

    if normalized_role_ids.is_empty() {
        return Ok(());
    }

    let mut transaction = pool.begin().await?;
    // Lock the user before checking class and writing roles so a concurrent
    // demotion cannot race a platform-role assignment.
    let user_class: String = sqlx::query("SELECT user_class FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .fetch_optional(&mut *transaction)
        .await?
        .map(|row| row.get("user_class"))
        .ok_or_else(|| anyhow::anyhow!("user_not_found"))?;
    let role_rows = sqlx::query(
        r#"
        SELECT id, assignable_to, scope
        FROM roles
        WHERE id = ANY($1)
        FOR SHARE
        "#,
    )
    .bind(&normalized_role_ids)
    .fetch_all(&mut *transaction)
    .await?;
    let mut roles_by_id = std::collections::HashMap::new();
    for row in role_rows {
        let role_id: String = row.get("id");
        let assignable_to: String = row.get("assignable_to");
        let scope: String = row.get("scope");
        roles_by_id.insert(role_id, (assignable_to, scope));
    }

    for role_id in &normalized_role_ids {
        let Some((assignable_to, scope)) = roles_by_id.get(role_id) else {
            anyhow::bail!("role_not_found");
        };
        ensure_user_can_receive_platform_role(role_id, assignable_to, scope, &user_class)?;
    }

    for role_id in &normalized_role_ids {
        sqlx::query(
            "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(role_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO principal_roles (principal_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(&principal.id)
        .bind(role_id)
        .execute(&mut *transaction)
        .await?;
    }

    transaction.commit().await?;
    Ok(())
}

/// 撤销用户的角色
pub async fn revoke_role_from_user(pool: &PgPool, user_id: &str, role_id: &str) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    let user_exists = sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .fetch_optional(&mut *transaction)
        .await?
        .is_some();
    if !user_exists {
        transaction.commit().await?;
        return Ok(false);
    }

    // User and Principal role rows are one logical assignment. Remove both
    // under one transaction so authorization cannot observe a half-revoked role.
    let user_result = sqlx::query("DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2")
        .bind(user_id)
        .bind(role_id)
        .execute(&mut *transaction)
        .await?;
    let principal_result = sqlx::query(
        "DELETE FROM principal_roles WHERE principal_id IN (SELECT id FROM principals WHERE principal_type = 'user' AND ref_id = $1) AND role_id = $2",
    )
    .bind(user_id)
    .bind(role_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    Ok(user_result.rows_affected() > 0 || principal_result.rows_affected() > 0)
}

/// 获取用户的所有角色
pub async fn get_user_roles(pool: &PgPool, user_id: &str) -> Result<Vec<Role>> {
    let roles = sqlx::query_as::<_, Role>(
        r#"
        SELECT r.id, r.name, r.description, r.assignable_to, r.system, r.version, r.created_at, r.updated_at
        FROM roles r
        INNER JOIN user_roles ur ON r.id = ur.role_id
        INNER JOIN users u ON u.id = ur.user_id
        WHERE ur.user_id = $1
          AND r.scope = 'platform'
          AND u.user_class = 'internal_employee'
        ORDER BY r.name
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(roles)
}

/// 获取角色的所有用户
pub async fn get_role_users(pool: &PgPool, role_id: &str) -> Result<Vec<String>> {
    let rows = sqlx::query("SELECT user_id FROM user_roles WHERE role_id = $1")
        .bind(role_id)
        .fetch_all(pool)
        .await?;

    Ok(rows.into_iter().map(|r| r.get("user_id")).collect())
}

/// 检查用户是否有特定角色
pub async fn user_has_role(pool: &PgPool, user_id: &str, role_name: &str) -> Result<bool> {
    let row = sqlx::query(
        r#"
        SELECT COUNT(*) as count
        FROM user_roles ur
        INNER JOIN roles r ON ur.role_id = r.id
        INNER JOIN users u ON u.id = ur.user_id
        WHERE ur.user_id = $1
          AND r.name = $2
          AND r.scope = 'platform'
          AND u.user_class = 'internal_employee'
        "#,
    )
    .bind(user_id)
    .bind(role_name)
    .fetch_one(pool)
    .await?;

    let count: i64 = row.get::<Option<i64>, _>("count").unwrap_or(0);
    Ok(count > 0)
}

/// Resolves live platform-admin authority for a human account.
/// This deliberately checks both account class and role scope so old customer
/// bindings cannot mint or keep management access.
pub async fn user_is_platform_admin(pool: &PgPool, user_id: &str) -> Result<bool> {
    let row = sqlx::query(
        r#"
        SELECT COUNT(*) AS count
        FROM users u
        INNER JOIN user_roles ur ON ur.user_id = u.id
        INNER JOIN roles r ON r.id = ur.role_id
        WHERE u.id = $1
          AND u.active = TRUE
          AND u.user_class = 'internal_employee'
          AND r.scope = 'platform'
          AND r.name IN ('super_admin', 'admin')
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let count: i64 = row.get::<Option<i64>, _>("count").unwrap_or(0);
    Ok(count > 0)
}

/// 角色权限关系操作
/// 为角色分配权限
pub async fn assign_permission_to_role(
    pool: &PgPool,
    role_id: &str,
    permission_id: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(role_id)
    .bind(permission_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// 为角色批量分配权限
pub async fn assign_permissions_to_role_batch(
    pool: &PgPool,
    role_id: &str,
    permission_ids: &[String],
) -> Result<()> {
    for permission_id in permission_ids {
        assign_permission_to_role(pool, role_id, permission_id).await?;
    }

    Ok(())
}

/// 撤销角色的权限
pub async fn revoke_permission_from_role(
    pool: &PgPool,
    role_id: &str,
    permission_id: &str,
) -> Result<bool> {
    let result =
        sqlx::query("DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2")
            .bind(role_id)
            .bind(permission_id)
            .execute(pool)
            .await?;

    Ok(result.rows_affected() > 0)
}

/// 获取角色的所有权限
pub async fn get_role_permissions(pool: &PgPool, role_id: &str) -> Result<Vec<Permission>> {
    let permissions = sqlx::query_as::<_, Permission>(
        r#"
        SELECT p.id, p.name, p.description, p.version, p.created_at, p.updated_at
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = $1
        ORDER BY p.name
        "#,
    )
    .bind(role_id)
    .fetch_all(pool)
    .await?;

    Ok(permissions)
}

/// 获取权限的所有角色
pub async fn get_permission_roles(pool: &PgPool, permission_id: &str) -> Result<Vec<String>> {
    let rows = sqlx::query("SELECT role_id FROM role_permissions WHERE permission_id = $1")
        .bind(permission_id)
        .fetch_all(pool)
        .await?;

    Ok(rows.into_iter().map(|r| r.get("role_id")).collect())
}

/// 检查用户是否有特定权限
pub async fn user_has_permission(
    pool: &PgPool,
    user_id: &str,
    permission_name: &str,
) -> Result<bool> {
    let row = sqlx::query(
        r#"
        SELECT COUNT(*) as count
        FROM user_roles ur
        INNER JOIN users u ON u.id = ur.user_id
        INNER JOIN roles r ON r.id = ur.role_id
        INNER JOIN role_permissions rp ON ur.role_id = rp.role_id
        INNER JOIN permissions p ON rp.permission_id = p.id
        WHERE ur.user_id = $1
          AND u.user_class = 'internal_employee'
          AND r.scope = 'platform'
          AND (p.name = $2 OR p.name = '*:*:*')
        "#,
    )
    .bind(user_id)
    .bind(permission_name)
    .fetch_one(pool)
    .await?;

    let count: i64 = row.get::<Option<i64>, _>("count").unwrap_or(0);
    Ok(count > 0)
}

/// 获取用户的所有权限（通过角色）
pub async fn get_user_permissions(pool: &PgPool, user_id: &str) -> Result<Vec<Permission>> {
    let permissions = sqlx::query_as::<_, Permission>(
        r#"
        SELECT DISTINCT p.id, p.name, p.description, p.version, p.created_at, p.updated_at
        FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        INNER JOIN user_roles ur ON rp.role_id = ur.role_id
        INNER JOIN users u ON u.id = ur.user_id
        INNER JOIN roles r ON r.id = ur.role_id
        WHERE ur.user_id = $1
          AND u.user_class = 'internal_employee'
          AND r.scope = 'platform'
        ORDER BY p.name
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(permissions)
}

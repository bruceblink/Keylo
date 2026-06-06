use anyhow::Result;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::models::{Permission, Principal, Role};

fn principal_id(principal_type: &str, ref_id: &str) -> String {
    format!("{}-{}", principal_type, ref_id)
}

fn subject(principal_type: &str, ref_id: &str) -> String {
    format!("{}:{}", principal_type, ref_id)
}

fn select_principal_sql() -> &'static str {
    "SELECT id, principal_type, subject, ref_id, display_name, active, created_at, updated_at FROM principals"
}

fn normalize_assignable_to(assignable_to: &str) -> &str {
    match assignable_to {
        "user" | "service" | "client" | "all" => assignable_to,
        _ => "all",
    }
}

pub async fn upsert_principal(
    pool: &PgPool,
    principal_type: &str,
    ref_id: &str,
    display_name: &str,
    active: bool,
) -> Result<Principal> {
    let id = principal_id(principal_type, ref_id);
    let subject = subject(principal_type, ref_id);

    let principal = sqlx::query_as::<_, Principal>(
        r#"
        INSERT INTO principals (id, principal_type, subject, ref_id, display_name, active)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (principal_type, ref_id) DO UPDATE
        SET subject = EXCLUDED.subject,
            display_name = EXCLUDED.display_name,
            active = EXCLUDED.active,
            updated_at = NOW()
        RETURNING id, principal_type, subject, ref_id, display_name, active, created_at, updated_at
        "#,
    )
    .bind(id)
    .bind(principal_type)
    .bind(subject)
    .bind(ref_id)
    .bind(display_name)
    .bind(active)
    .fetch_one(pool)
    .await?;

    Ok(principal)
}

pub async fn get_principal_by_id(pool: &PgPool, principal_id: &str) -> Result<Option<Principal>> {
    let sql = format!("{} WHERE id = $1", select_principal_sql());
    Ok(sqlx::query_as::<_, Principal>(&sql)
        .bind(principal_id)
        .fetch_optional(pool)
        .await?)
}

pub async fn get_principal_by_ref(
    pool: &PgPool,
    principal_type: &str,
    ref_id: &str,
) -> Result<Option<Principal>> {
    let sql = format!(
        "{} WHERE principal_type = $1 AND ref_id = $2",
        select_principal_sql()
    );
    Ok(sqlx::query_as::<_, Principal>(&sql)
        .bind(principal_type)
        .bind(ref_id)
        .fetch_optional(pool)
        .await?)
}

pub async fn get_principal_by_subject(pool: &PgPool, subject: &str) -> Result<Option<Principal>> {
    let sql = format!("{} WHERE subject = $1", select_principal_sql());
    Ok(sqlx::query_as::<_, Principal>(&sql)
        .bind(subject)
        .fetch_optional(pool)
        .await?)
}

pub async fn list_principals(
    pool: &PgPool,
    principal_type: Option<&str>,
    active: Option<bool>,
    limit: i64,
    offset: i64,
) -> Result<Vec<Principal>> {
    let rows = sqlx::query_as::<_, Principal>(
        r#"
        SELECT id, principal_type, subject, ref_id, display_name, active, created_at, updated_at
        FROM principals
        WHERE ($1::text IS NULL OR principal_type = $1)
          AND ($2::boolean IS NULL OR active = $2)
        ORDER BY updated_at DESC, id
        LIMIT $3 OFFSET $4
        "#,
    )
    .bind(principal_type)
    .bind(active)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

pub async fn ensure_user_principal(pool: &PgPool, user_id: &str) -> Result<Option<Principal>> {
    let row = sqlx::query("SELECT username, active FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

    match row {
        Some(row) => {
            let username: String = row.get("username");
            let active: bool = row.get("active");
            Ok(Some(
                upsert_principal(pool, "user", user_id, &username, active).await?,
            ))
        }
        None => Ok(None),
    }
}

pub async fn ensure_client_principal(pool: &PgPool, client_id: &str) -> Result<Option<Principal>> {
    let row = sqlx::query("SELECT name, active FROM clients WHERE id = $1")
        .bind(client_id)
        .fetch_optional(pool)
        .await?;

    match row {
        Some(row) => {
            let name: String = row.get("name");
            let active: bool = row.get("active");
            Ok(Some(
                upsert_principal(pool, "client", client_id, &name, active).await?,
            ))
        }
        None => Ok(None),
    }
}

pub async fn ensure_service_principal(
    pool: &PgPool,
    service_id: &str,
) -> Result<Option<Principal>> {
    let row = sqlx::query("SELECT name, active FROM service_clients WHERE service_id = $1")
        .bind(service_id)
        .fetch_optional(pool)
        .await?;

    match row {
        Some(row) => {
            let name: String = row.get("name");
            let active: bool = row.get("active");
            Ok(Some(
                upsert_principal(pool, "service", service_id, &name, active).await?,
            ))
        }
        None => Ok(None),
    }
}

pub async fn assign_role_to_principal(
    pool: &PgPool,
    principal_id: &str,
    role_id: &str,
) -> Result<()> {
    let row = sqlx::query(
        r#"
        SELECT p.principal_type, r.assignable_to
        FROM principals p
        CROSS JOIN roles r
        WHERE p.id = $1 AND r.id = $2
        "#,
    )
    .bind(principal_id)
    .bind(role_id)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        anyhow::bail!("principal_or_role_not_found");
    };

    let principal_type: String = row.get("principal_type");
    let assignable_to: String = row.get("assignable_to");
    let assignable_to = normalize_assignable_to(&assignable_to);
    if assignable_to != "all" && assignable_to != principal_type {
        anyhow::bail!(
            "role_not_assignable_to_principal_type: role={}, principal_type={}",
            role_id,
            principal_type
        );
    }

    sqlx::query(
        "INSERT INTO principal_roles (principal_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(principal_id)
    .bind(role_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn sync_user_roles_to_principal(pool: &PgPool, user_id: &str) -> Result<()> {
    let Some(principal) = ensure_user_principal(pool, user_id).await? else {
        return Ok(());
    };

    sqlx::query(
        r#"
        INSERT INTO principal_roles (principal_id, role_id, assigned_at)
        SELECT $1, role_id, assigned_at
        FROM user_roles
        WHERE user_id = $2
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(&principal.id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn revoke_role_from_principal(
    pool: &PgPool,
    principal_id: &str,
    role_id: &str,
) -> Result<bool> {
    let result =
        sqlx::query("DELETE FROM principal_roles WHERE principal_id = $1 AND role_id = $2")
            .bind(principal_id)
            .bind(role_id)
            .execute(pool)
            .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn get_principal_roles(pool: &PgPool, principal_id: &str) -> Result<Vec<Role>> {
    Ok(sqlx::query_as::<_, Role>(
        r#"
        SELECT r.id, r.name, r.description, r.assignable_to, r.system, r.created_at, r.updated_at
        FROM roles r
        INNER JOIN principal_roles pr ON pr.role_id = r.id
        WHERE pr.principal_id = $1
        ORDER BY r.name
        "#,
    )
    .bind(principal_id)
    .fetch_all(pool)
    .await?)
}

pub async fn get_principal_permissions(
    pool: &PgPool,
    principal_id: &str,
) -> Result<Vec<Permission>> {
    Ok(sqlx::query_as::<_, Permission>(
        r#"
        SELECT DISTINCT p.id, p.name, p.description, p.created_at, p.updated_at
        FROM permissions p
        INNER JOIN role_permissions rp ON rp.permission_id = p.id
        INNER JOIN principal_roles pr ON pr.role_id = rp.role_id
        WHERE pr.principal_id = $1
        ORDER BY p.name
        "#,
    )
    .bind(principal_id)
    .fetch_all(pool)
    .await?)
}

pub async fn principal_has_permission(
    pool: &PgPool,
    principal_id: &str,
    permission_name: &str,
) -> Result<bool> {
    let row = sqlx::query(
        r#"
        SELECT 1
        FROM principal_roles pr
        INNER JOIN role_permissions rp ON rp.role_id = pr.role_id
        INNER JOIN permissions p ON p.id = rp.permission_id
        WHERE pr.principal_id = $1 AND (p.name = $2 OR p.name = '*:*:*')
        LIMIT 1
        "#,
    )
    .bind(principal_id)
    .bind(permission_name)
    .fetch_optional(pool)
    .await?;

    Ok(row.is_some())
}

pub async fn principal_has_wildcard_permission(pool: &PgPool, principal_id: &str) -> Result<bool> {
    let row = sqlx::query(
        r#"
        SELECT 1
        FROM principal_roles pr
        INNER JOIN role_permissions rp ON rp.role_id = pr.role_id
        INNER JOIN permissions p ON p.id = rp.permission_id
        WHERE pr.principal_id = $1 AND p.name = '*:*:*'
        LIMIT 1
        "#,
    )
    .bind(principal_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.is_some())
}

pub async fn permission_for_resource(
    pool: &PgPool,
    app: &str,
    resource_type: &str,
    resource_code: &str,
) -> Result<Option<String>> {
    let row = sqlx::query(
        r#"
        SELECT p.name
        FROM resources r
        INNER JOIN resource_permissions rp ON rp.resource_id = r.id
        INNER JOIN permissions p ON p.id = rp.permission_id
        WHERE r.app = $1 AND r.resource_type = $2 AND r.code = $3 AND r.active = TRUE
        ORDER BY p.name
        LIMIT 1
        "#,
    )
    .bind(app)
    .bind(resource_type)
    .bind(resource_code)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| row.get("name")))
}

pub async fn create_authorization_audit_log(
    pool: &PgPool,
    principal_id: Option<&str>,
    decision: &str,
    permission_name: Option<&str>,
    resource_id: Option<&str>,
    detail: Option<&str>,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO authorization_audit_logs
            (id, principal_id, decision, permission_name, resource_id, detail)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(principal_id)
    .bind(decision)
    .bind(permission_name)
    .bind(resource_id)
    .bind(detail)
    .execute(pool)
    .await?;

    Ok(())
}

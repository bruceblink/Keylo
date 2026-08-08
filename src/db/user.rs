use anyhow::Result;
use bcrypt::{hash, verify, DEFAULT_COST};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use sqlx::Row;
use uuid::Uuid;

use crate::models::User;

const PASSWORD_COST: u32 = DEFAULT_COST;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalUserMappingUnlinkResult {
    Unlinked,
    NotFound,
    LastLoginMethod,
}

#[derive(Debug, Clone)]
pub struct ExternalUserMapping {
    pub user_id: String,
    pub metadata: Option<Value>,
}

fn hash_password(password: &str) -> Result<String> {
    Ok(hash(password, PASSWORD_COST)?)
}

fn verify_password_hash(password: &str, password_hash: &str) -> Result<bool> {
    Ok(verify(password, password_hash)?)
}

/// Derive the database lookup key for an external subject without retaining the subject itself.
fn external_subject_hash(external_user_id: &str) -> String {
    hex::encode(Sha256::digest(external_user_id.as_bytes()))
}

/// 获取用户
pub async fn get_user_by_id(pool: &PgPool, user_id: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, email_verified, password_hash, active, created_at, updated_at FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// 根据用户名获取用户
pub async fn get_user_by_username(pool: &PgPool, username: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, email_verified, password_hash, active, created_at, updated_at FROM users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// 根据邮箱获取用户
pub async fn get_user_by_email(pool: &PgPool, email: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, email_verified, password_hash, active, created_at, updated_at FROM users WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// 列出用户，支持分页
pub async fn list_users(pool: &PgPool, limit: i64, offset: i64) -> Result<Vec<User>> {
    let users = sqlx::query_as::<_, User>(
        "SELECT id, username, email, email_verified, password_hash, active, created_at, updated_at FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(users)
}

/// 创建用户，并将本地邮箱默认为未验证。
pub async fn create_user(
    pool: &PgPool,
    username: &str,
    email: &str,
    password: Option<&str>,
) -> Result<User> {
    create_user_with_email_verified(pool, username, email, password, false).await
}

/// Create a user with an explicitly trusted email verification state.
///
/// Only verified upstream OIDC claims should pass `email_verified = true`; local
/// registration and administrative provisioning use `create_user` instead.
pub async fn create_user_with_email_verified(
    pool: &PgPool,
    username: &str,
    email: &str,
    password: Option<&str>,
    email_verified: bool,
) -> Result<User> {
    let id = Uuid::new_v4().to_string();
    let password_hash = if let Some(p) = password {
        Some(hash_password(p)?)
    } else {
        None
    };
    let now = chrono::Local::now().naive_utc();

    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (id, username, email, email_verified, password_hash, active, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7)
        RETURNING id, username, email, email_verified, password_hash, active, created_at, updated_at
        "#,
    )
    .bind(id)
    .bind(username)
    .bind(email)
    .bind(email_verified)
    .bind(password_hash)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    crate::db::ensure_user_principal(pool, &user.id).await?;

    Ok(user)
}

/// 更新用户
pub async fn update_user(
    pool: &PgPool,
    user_id: &str,
    username: Option<&str>,
    email: Option<&str>,
    password: Option<&str>,
    active: Option<bool>,
    actor: Option<&str>,
) -> Result<Option<User>> {
    let password_hash = if let Some(p) = password {
        Some(hash_password(p)?)
    } else {
        None
    };
    let now = chrono::Local::now().naive_utc();

    let mut transaction = pool.begin().await?;
    let user = sqlx::query_as::<_, User>(
        r#"
        UPDATE users
        SET username = COALESCE($2, username),
            email = COALESCE($3, email),
            email_verified = CASE
                WHEN $3 IS NOT NULL AND email IS DISTINCT FROM $3 THEN FALSE
                ELSE email_verified
            END,
            password_hash = COALESCE($4, password_hash),
            active = COALESCE($5, active),
            updated_at = $6
        WHERE id = $1
        RETURNING id, username, email, email_verified, password_hash, active, created_at, updated_at
        "#,
    )
    .bind(user_id)
    .bind(username)
    .bind(email)
    .bind(password_hash)
    .bind(active)
    .bind(now)
    .fetch_optional(&mut *transaction)
    .await?;

    if let Some(user) = &user {
        if active == Some(false) || password.is_some() {
            let (event_type, revoke_reason) = if active == Some(false) {
                ("user.disabled", "user_disabled")
            } else {
                ("user.password_updated", "password_updated")
            };
            // Credential and status changes must invalidate every long-lived session atomically.
            let revoked_refresh_sessions = sqlx::query(
                "UPDATE refresh_sessions SET revoked_at = COALESCE(revoked_at, NOW()), revoke_reason = COALESCE(revoke_reason, $2) WHERE principal_id IN (SELECT id FROM principals WHERE principal_type = 'user' AND ref_id = $1) AND revoked_at IS NULL",
            )
            .bind(&user.id)
            .bind(revoke_reason)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            let revoked_browser_sessions = sqlx::query(
                "UPDATE oidc_browser_sessions SET revoked_at = COALESCE(revoked_at, NOW()) WHERE user_id = $1 AND revoked_at IS NULL",
            )
            .bind(&user.id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            sqlx::query(
                "INSERT INTO audit_logs (id, event_type, actor, detail) VALUES ($1, $2, $3, $4)",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(event_type)
            .bind(actor)
            .bind(format!(
                "user_id={}; revoked_refresh_sessions={}; revoked_oidc_browser_sessions={}",
                user.id, revoked_refresh_sessions, revoked_browser_sessions
            ))
            .execute(&mut *transaction)
            .await?;
        }
    }
    transaction.commit().await?;

    if let Some(user) = &user {
        crate::db::ensure_user_principal(pool, &user.id).await?;
    }

    Ok(user)
}

/// 更新用户激活状态
pub async fn set_user_active(pool: &PgPool, user_id: &str, active: bool) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    let result = sqlx::query("UPDATE users SET active = $2, updated_at = $3 WHERE id = $1")
        .bind(user_id)
        .bind(active)
        .bind(chrono::Local::now().naive_utc())
        .execute(&mut *transaction)
        .await?;
    if result.rows_affected() == 0 {
        transaction.commit().await?;
        return Ok(false);
    }
    if !active {
        // Keep non-HTTP callers subject to the same session invalidation policy.
        let revoked_refresh_sessions = sqlx::query(
            "UPDATE refresh_sessions SET revoked_at = COALESCE(revoked_at, NOW()), revoke_reason = COALESCE(revoke_reason, 'user_disabled') WHERE principal_id IN (SELECT id FROM principals WHERE principal_type = 'user' AND ref_id = $1) AND revoked_at IS NULL",
        )
        .bind(user_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let revoked_browser_sessions = sqlx::query(
            "UPDATE oidc_browser_sessions SET revoked_at = COALESCE(revoked_at, NOW()) WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        sqlx::query(
            "INSERT INTO audit_logs (id, event_type, actor, detail) VALUES ($1, $2, $3, $4)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind("user.disabled")
        .bind(Option::<&str>::None)
        .bind(format!(
            "user_id={}; revoked_refresh_sessions={}; revoked_oidc_browser_sessions={}",
            user_id, revoked_refresh_sessions, revoked_browser_sessions
        ))
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;

    Ok(true)
}

/// Delete a user and invalidate all sessions that can outlive the user row.
pub async fn delete_user(pool: &PgPool, user_id: &str, actor: Option<&str>) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 FOR UPDATE)",
    )
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await?;
    if !exists {
        transaction.commit().await?;
        return Ok(false);
    }
    let revoked_refresh_sessions = sqlx::query(
        "UPDATE refresh_sessions SET revoked_at = COALESCE(revoked_at, NOW()), revoke_reason = COALESCE(revoke_reason, 'user_deleted') WHERE principal_id IN (SELECT id FROM principals WHERE principal_type = 'user' AND ref_id = $1) AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    let deleted_browser_sessions =
        sqlx::query("DELETE FROM oidc_browser_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
    // Principal roles cascade from this delete, preventing orphaned authorization subjects.
    let deleted_principals =
        sqlx::query("DELETE FROM principals WHERE principal_type = 'user' AND ref_id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("INSERT INTO audit_logs (id, event_type, actor, detail) VALUES ($1, $2, $3, $4)")
        .bind(Uuid::new_v4().to_string())
        .bind("user.deleted")
        .bind(actor)
        .bind(format!(
            "user_id={}; revoked_refresh_sessions={}; deleted_oidc_browser_sessions={}; deleted_principals={}",
            user_id, revoked_refresh_sessions, deleted_browser_sessions, deleted_principals
        ))
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(true)
}

/// 验证用户凭证
pub async fn validate_user_credentials(
    pool: &PgPool,
    username: &str,
    password: &str,
) -> Result<Option<User>> {
    if let Some(user) = get_user_by_username(pool, username).await? {
        if !user.active {
            return Ok(None);
        }

        if let Some(password_hash) = user.password_hash.as_deref() {
            if verify_password_hash(password, password_hash)? {
                return Ok(Some(user));
            }
        }
    }

    Ok(None)
}

/// Reset an account password and revoke existing sessions before the new credential is usable.
pub async fn reset_user_password(
    pool: &PgPool,
    user_id: &str,
    password: &str,
    actor: Option<&str>,
) -> Result<bool> {
    let password_hash = hash_password(password)?;
    let mut transaction = pool.begin().await?;
    let updated = sqlx::query("UPDATE users SET password_hash = $2, updated_at = $3 WHERE id = $1")
        .bind(user_id)
        .bind(password_hash)
        .bind(chrono::Local::now().naive_utc())
        .execute(&mut *transaction)
        .await?
        .rows_affected()
        > 0;
    if !updated {
        transaction.commit().await?;
        return Ok(false);
    }
    let revoked_refresh_sessions = sqlx::query(
        "UPDATE refresh_sessions SET revoked_at = COALESCE(revoked_at, NOW()), revoke_reason = COALESCE(revoke_reason, 'password_reset') WHERE principal_id IN (SELECT id FROM principals WHERE principal_type = 'user' AND ref_id = $1) AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    let revoked_browser_sessions = sqlx::query(
        "UPDATE oidc_browser_sessions SET revoked_at = COALESCE(revoked_at, NOW()) WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    sqlx::query("INSERT INTO audit_logs (id, event_type, actor, detail) VALUES ($1, $2, $3, $4)")
        .bind(Uuid::new_v4().to_string())
        .bind("user.password_reset")
        .bind(actor)
        .bind(format!(
            "user_id={}; revoked_refresh_sessions={}; revoked_oidc_browser_sessions={}",
            user_id, revoked_refresh_sessions, revoked_browser_sessions
        ))
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(true)
}

/// Mark a local email as verified once a trusted identity source confirms it.
///
/// The transition is one-way here: changing a local email resets the flag, while
/// a future email-verification workflow can explicitly establish it again.
pub async fn mark_user_email_verified(
    pool: &PgPool,
    user_id: &str,
    actor: Option<&str>,
) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    let updated = sqlx::query(
        "UPDATE users SET email_verified = TRUE, updated_at = $2 WHERE id = $1 AND email_verified = FALSE",
    )
    .bind(user_id)
    .bind(chrono::Local::now().naive_utc())
    .execute(&mut *transaction)
    .await?
    .rows_affected()
        > 0;
    if !updated {
        transaction.commit().await?;
        return Ok(false);
    }

    sqlx::query("INSERT INTO audit_logs (id, event_type, actor, detail) VALUES ($1, $2, $3, $4)")
        .bind(Uuid::new_v4().to_string())
        .bind("user.email_verified")
        .bind(actor)
        .bind(format!("user_id={}", user_id))
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(true)
}

/// 用户更改密码（需要验证当前密码）
pub async fn change_user_password(
    pool: &PgPool,
    user_id: &str,
    current_password: &str,
    new_password: &str,
    actor: Option<&str>,
) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    // Lock the account so concurrent password changes cannot both validate the same old password.
    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, email_verified, password_hash, active, created_at, updated_at FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some(user) = user {
        if !user.active {
            transaction.commit().await?;
            return Ok(false);
        }

        if let Some(password_hash) = user.password_hash.as_deref() {
            if !verify_password_hash(current_password, password_hash)? {
                transaction.commit().await?;
                return Ok(false); // 当前密码不正确
            }
        } else {
            transaction.commit().await?;
            return Ok(false); // 用户没有密码
        }
    } else {
        transaction.commit().await?;
        return Ok(false); // 用户不存在
    }

    // Update the credential and invalidate every session type in one transaction.
    let new_password_hash = hash_password(new_password)?;
    let updated = sqlx::query("UPDATE users SET password_hash = $2, updated_at = $3 WHERE id = $1")
        .bind(user_id)
        .bind(new_password_hash)
        .bind(chrono::Local::now().naive_utc())
        .execute(&mut *transaction)
        .await?
        .rows_affected()
        > 0;
    if !updated {
        transaction.commit().await?;
        return Ok(false);
    }
    let revoked_refresh_sessions = sqlx::query(
        "UPDATE refresh_sessions
         SET revoked_at = COALESCE(revoked_at, NOW()),
             revoke_reason = COALESCE(revoke_reason, 'password_changed')
         WHERE principal_id IN (
             SELECT id FROM principals WHERE principal_type = 'user' AND ref_id = $1
         ) AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    let revoked_browser_sessions = sqlx::query(
        "UPDATE oidc_browser_sessions
         SET revoked_at = COALESCE(revoked_at, NOW())
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    sqlx::query("INSERT INTO audit_logs (id, event_type, actor, detail) VALUES ($1, $2, $3, $4)")
        .bind(Uuid::new_v4().to_string())
        .bind("user.password_changed")
        .bind(actor)
        .bind(format!(
            "user_id={}; revoked_refresh_sessions={}; revoked_oidc_browser_sessions={}",
            user_id, revoked_refresh_sessions, revoked_browser_sessions
        ))
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;

    Ok(true)
}

/// 根据外部系统映射查询用户ID
pub async fn get_mapped_user_id(
    pool: &PgPool,
    provider: &str,
    external_user_id: &str,
) -> Result<Option<String>> {
    let external_subject_hash = external_subject_hash(external_user_id);
    let row = sqlx::query(
        "SELECT user_id FROM external_user_mappings WHERE provider = $1 AND external_user_id = $2",
    )
    .bind(provider)
    .bind(external_subject_hash)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|value| value.get("user_id")))
}

/// Load one external binding with its non-secret metadata for policy decisions.
pub async fn get_external_user_mapping(
    pool: &PgPool,
    provider: &str,
    external_user_id: &str,
) -> Result<Option<ExternalUserMapping>> {
    let external_subject_hash = external_subject_hash(external_user_id);
    let row = sqlx::query(
        "SELECT user_id, metadata FROM external_user_mappings WHERE provider = $1 AND external_user_id = $2",
    )
    .bind(provider)
    .bind(external_subject_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| ExternalUserMapping {
        user_id: row.get("user_id"),
        metadata: row.get("metadata"),
    }))
}

/// Store the last observed external email without changing the immutable subject-to-user binding.
pub async fn update_external_user_mapping_email(
    pool: &PgPool,
    provider: &str,
    external_user_id: &str,
    user_id: &str,
    metadata: &Value,
) -> Result<bool> {
    let external_subject_hash = external_subject_hash(external_user_id);
    let result = sqlx::query(
        "UPDATE external_user_mappings SET metadata = $5, updated_at = $6 WHERE provider = $1 AND external_user_id = $2 AND user_id = $3 AND metadata IS DISTINCT FROM $4",
    )
    .bind(provider)
    .bind(external_subject_hash)
    .bind(user_id)
    .bind(metadata)
    .bind(metadata)
    .bind(chrono::Local::now().naive_utc())
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// 创建或更新外部系统用户映射
pub async fn upsert_external_user_mapping(
    pool: &PgPool,
    provider: &str,
    external_user_id: &str,
    user_id: &str,
    metadata: Option<&Value>,
) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Local::now().naive_utc();
    let external_subject_hash = external_subject_hash(external_user_id);

    sqlx::query(
        r#"
        INSERT INTO external_user_mappings
            (id, provider, external_user_id, user_id, metadata, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $6)
        ON CONFLICT (provider, external_user_id) DO UPDATE
            SET user_id = EXCLUDED.user_id,
                metadata = EXCLUDED.metadata,
                updated_at = EXCLUDED.updated_at
        "#,
    )
    .bind(id)
    .bind(provider)
    .bind(external_subject_hash)
    .bind(user_id)
    .bind(metadata)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Create an immutable external identity binding; callers must never reassign an existing subject.
pub async fn create_external_user_mapping(
    pool: &PgPool,
    provider: &str,
    external_user_id: &str,
    user_id: &str,
    metadata: Option<&Value>,
) -> Result<()> {
    let now = chrono::Local::now().naive_utc();
    let external_subject_hash = external_subject_hash(external_user_id);
    sqlx::query(
        r#"
        INSERT INTO external_user_mappings
            (id, provider, external_user_id, user_id, metadata, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $6)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(provider)
    .bind(external_subject_hash)
    .bind(user_id)
    .bind(metadata)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Remove one upstream source from a user only when another login method remains available.
pub async fn unlink_external_user_mapping(
    pool: &PgPool,
    provider: &str,
    user_id: &str,
) -> Result<ExternalUserMappingUnlinkResult> {
    let mut tx = pool.begin().await?;
    let user = sqlx::query(
        "SELECT password_hash IS NOT NULL AS has_password FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(user) = user else {
        tx.commit().await?;
        return Ok(ExternalUserMappingUnlinkResult::NotFound);
    };
    let mapping_exists = sqlx::query(
        "SELECT 1 FROM external_user_mappings WHERE provider = $1 AND user_id = $2 LIMIT 1",
    )
    .bind(provider)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    if !mapping_exists {
        tx.commit().await?;
        return Ok(ExternalUserMappingUnlinkResult::NotFound);
    }

    let has_password: bool = user.get("has_password");
    let has_other_external_mapping = sqlx::query(
        "SELECT 1 FROM external_user_mappings WHERE user_id = $1 AND provider <> $2 LIMIT 1",
    )
    .bind(user_id)
    .bind(provider)
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    let has_oauth_account =
        sqlx::query("SELECT 1 FROM user_oauth_accounts WHERE user_id = $1 LIMIT 1")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
    if !has_password && !has_other_external_mapping && !has_oauth_account {
        tx.commit().await?;
        return Ok(ExternalUserMappingUnlinkResult::LastLoginMethod);
    }

    sqlx::query("DELETE FROM external_user_mappings WHERE provider = $1 AND user_id = $2")
        .bind(provider)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(ExternalUserMappingUnlinkResult::Unlinked)
}

/// 获取用户总量
pub async fn count_users(pool: &PgPool) -> Result<i64> {
    let row = sqlx::query("SELECT COUNT(*) AS count FROM users")
        .fetch_one(pool)
        .await?;

    Ok(row.get::<Option<i64>, _>("count").unwrap_or(0))
}

/// 原子创建用户并绑定角色模板（role_id + role_name）
pub async fn provision_user_with_roles(
    pool: &PgPool,
    username: &str,
    email: &str,
    password: Option<&str>,
    role_ids: &[String],
    role_names: &[String],
) -> Result<(
    User,
    Vec<crate::models::Role>,
    Vec<crate::models::Permission>,
)> {
    let mut tx = pool.begin().await?;

    let user_id = Uuid::new_v4().to_string();
    let password_hash = if let Some(p) = password {
        Some(hash_password(p)?)
    } else {
        None
    };
    let now = chrono::Local::now().naive_utc();

    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (id, username, email, email_verified, password_hash, active, created_at, updated_at)
        VALUES ($1, $2, $3, FALSE, $4, TRUE, $5, $6)
        RETURNING id, username, email, email_verified, password_hash, active, created_at, updated_at
        "#,
    )
    .bind(&user_id)
    .bind(username)
    .bind(email)
    .bind(password_hash)
    .bind(now)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;

    let mut normalized_role_ids: Vec<String> = role_ids
        .iter()
        .map(|role_id| role_id.trim().to_string())
        .filter(|role_id| !role_id.is_empty())
        .collect();

    if !role_names.is_empty() {
        let rows = sqlx::query(
            r#"
            SELECT id, name
            FROM roles
            WHERE name = ANY($1)
            "#,
        )
        .bind(role_names)
        .fetch_all(&mut *tx)
        .await?;

        let mut found_names = std::collections::HashSet::new();
        for row in rows {
            let role_id: String = row.get("id");
            let role_name: String = row.get("name");
            found_names.insert(role_name);
            normalized_role_ids.push(role_id);
        }

        for role_name in role_names {
            if !found_names.contains(role_name) {
                anyhow::bail!("role_not_bound: role name not found: {}", role_name);
            }
        }
    }

    normalized_role_ids.sort();
    normalized_role_ids.dedup();

    if !normalized_role_ids.is_empty() {
        let rows = sqlx::query(
            r#"
            SELECT id, assignable_to
            FROM roles
            WHERE id = ANY($1)
            "#,
        )
        .bind(&normalized_role_ids)
        .fetch_all(&mut *tx)
        .await?;

        let mut assignable_by_role_id = std::collections::HashMap::new();
        for row in rows {
            let role_id: String = row.get("id");
            let assignable_to: String = row.get("assignable_to");
            assignable_by_role_id.insert(role_id, assignable_to);
        }

        for role_id in &normalized_role_ids {
            let Some(assignable_to) = assignable_by_role_id.get(role_id) else {
                anyhow::bail!("role_not_bound: role id not found: {}", role_id);
            };
            crate::db::ensure_role_assignable_to_principal_type(role_id, assignable_to, "user")?;
        }
    }

    for role_id in normalized_role_ids {
        sqlx::query(
            "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(&user_id)
        .bind(role_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    crate::db::sync_user_roles_to_principal(pool, &user_id).await?;

    let roles = crate::db::get_user_roles(pool, &user_id).await?;
    let permissions = crate::db::get_user_permissions(pool, &user_id).await?;

    Ok((user, roles, permissions))
}

/// 查询用户最终权限并集
pub async fn get_effective_permissions(
    pool: &PgPool,
    user_id: &str,
) -> Result<(Vec<crate::models::Role>, Vec<crate::models::Permission>)> {
    crate::db::sync_user_roles_to_principal(pool, user_id).await?;

    let Some(principal) = crate::db::get_principal_by_ref(pool, "user", user_id).await? else {
        return Ok((Vec::new(), Vec::new()));
    };

    let roles = crate::db::get_principal_roles(pool, &principal.id).await?;
    let permissions = crate::db::get_principal_permissions(pool, &principal.id).await?;
    Ok((roles, permissions))
}

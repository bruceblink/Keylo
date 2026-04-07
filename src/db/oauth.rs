use anyhow::Result;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::models::*;

/// OAuth提供商相关数据库操作
/// 创建OAuth提供商
#[allow(clippy::too_many_arguments)]
pub async fn create_oauth_provider(
    pool: &PgPool,
    name: &str,
    client_id: &str,
    client_secret: &str,
    authorization_url: &str,
    token_url: &str,
    user_info_url: &str,
    scope: &str,
    redirect_url: &str,
) -> Result<OAuthProvider> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Local::now().naive_utc();

    let provider = sqlx::query_as::<_, OAuthProvider>(
        r#"
        INSERT INTO oauth_providers (
            id, name, client_id, client_secret, authorization_url,
            token_url, user_info_url, scope, redirect_url, active, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING id, name, client_id, client_secret, authorization_url,
                  token_url, user_info_url, scope, redirect_url, active, created_at, updated_at
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(client_id)
    .bind(client_secret)
    .bind(authorization_url)
    .bind(token_url)
    .bind(user_info_url)
    .bind(scope)
    .bind(redirect_url)
    .bind(true)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(provider)
}

/// 获取所有OAuth提供商
pub async fn get_all_oauth_providers(pool: &PgPool) -> Result<Vec<OAuthProvider>> {
    let providers = sqlx::query_as::<_, OAuthProvider>(
        "SELECT id, name, client_id, client_secret, authorization_url,
                token_url, user_info_url, scope, redirect_url, active, created_at, updated_at
         FROM oauth_providers WHERE active = TRUE ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    Ok(providers)
}

/// 根据ID获取OAuth提供商
pub async fn get_oauth_provider_by_id(
    pool: &PgPool,
    provider_id: &str,
) -> Result<Option<OAuthProvider>> {
    let provider = sqlx::query_as::<_, OAuthProvider>(
        "SELECT id, name, client_id, client_secret, authorization_url,
                token_url, user_info_url, scope, redirect_url, active, created_at, updated_at
         FROM oauth_providers WHERE id = $1 AND active = TRUE",
    )
    .bind(provider_id)
    .fetch_optional(pool)
    .await?;

    Ok(provider)
}

/// 根据名称获取OAuth提供商
pub async fn get_oauth_provider_by_name(
    pool: &PgPool,
    name: &str,
) -> Result<Option<OAuthProvider>> {
    let provider = sqlx::query_as::<_, OAuthProvider>(
        "SELECT id, name, client_id, client_secret, authorization_url,
                token_url, user_info_url, scope, redirect_url, active, created_at, updated_at
         FROM oauth_providers WHERE name = $1 AND active = TRUE",
    )
    .bind(name)
    .fetch_optional(pool)
    .await?;

    Ok(provider)
}

/// 更新OAuth提供商
#[allow(clippy::too_many_arguments)]
pub async fn update_oauth_provider(
    pool: &PgPool,
    provider_id: &str,
    name: Option<&str>,
    client_id: Option<&str>,
    client_secret: Option<&str>,
    authorization_url: Option<&str>,
    token_url: Option<&str>,
    user_info_url: Option<&str>,
    scope: Option<&str>,
    redirect_url: Option<&str>,
    active: Option<bool>,
) -> Result<Option<OAuthProvider>> {
    let now = chrono::Local::now().naive_utc();

    let provider = sqlx::query_as::<_, OAuthProvider>(
        r#"
        UPDATE oauth_providers
        SET name = COALESCE($2, name),
            client_id = COALESCE($3, client_id),
            client_secret = COALESCE($4, client_secret),
            authorization_url = COALESCE($5, authorization_url),
            token_url = COALESCE($6, token_url),
            user_info_url = COALESCE($7, user_info_url),
            scope = COALESCE($8, scope),
            redirect_url = COALESCE($9, redirect_url),
            active = COALESCE($10, active),
            updated_at = $11
        WHERE id = $1
        RETURNING id, name, client_id, client_secret, authorization_url,
                  token_url, user_info_url, scope, redirect_url, active, created_at, updated_at
        "#,
    )
    .bind(provider_id)
    .bind(name)
    .bind(client_id)
    .bind(client_secret)
    .bind(authorization_url)
    .bind(token_url)
    .bind(user_info_url)
    .bind(scope)
    .bind(redirect_url)
    .bind(active)
    .bind(now)
    .fetch_optional(pool)
    .await?;

    Ok(provider)
}

/// 删除OAuth提供商
pub async fn delete_oauth_provider(pool: &PgPool, provider_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM oauth_providers WHERE id = $1")
        .bind(provider_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// 用户OAuth账户关联操作
/// 关联用户OAuth账户
#[allow(clippy::too_many_arguments)]
pub async fn link_oauth_account(
    pool: &PgPool,
    user_id: &str,
    provider_id: &str,
    provider_user_id: &str,
    provider_username: Option<&str>,
    provider_email: Option<&str>,
    access_token: Option<&str>,
    refresh_token: Option<&str>,
    token_expires_at: Option<chrono::NaiveDateTime>,
) -> Result<UserOAuthAccount> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Local::now().naive_utc();

    let account = sqlx::query_as::<_, UserOAuthAccount>(
        r#"
        INSERT INTO user_oauth_accounts (
            id, user_id, provider_id, provider_user_id, provider_username,
            provider_email, access_token, refresh_token, token_expires_at,
            linked_at, last_login_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING id, user_id, provider_id, provider_user_id, provider_username,
                  provider_email, access_token, refresh_token, token_expires_at,
                  linked_at, last_login_at
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(provider_id)
    .bind(provider_user_id)
    .bind(provider_username)
    .bind(provider_email)
    .bind(access_token)
    .bind(refresh_token)
    .bind(token_expires_at)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(account)
}

/// 更新OAuth账户token信息
pub async fn update_oauth_account_tokens(
    pool: &PgPool,
    account_id: &str,
    access_token: Option<&str>,
    refresh_token: Option<&str>,
    token_expires_at: Option<chrono::NaiveDateTime>,
) -> Result<Option<UserOAuthAccount>> {
    let now = chrono::Local::now().naive_utc();

    let account = sqlx::query_as::<_, UserOAuthAccount>(
        r#"
        UPDATE user_oauth_accounts
        SET access_token = COALESCE($2, access_token),
            refresh_token = COALESCE($3, refresh_token),
            token_expires_at = COALESCE($4, token_expires_at),
            last_login_at = $5
        WHERE id = $1
        RETURNING id, user_id, provider_id, provider_user_id, provider_username,
                  provider_email, access_token, refresh_token, token_expires_at,
                  linked_at, last_login_at
        "#,
    )
    .bind(account_id)
    .bind(access_token)
    .bind(refresh_token)
    .bind(token_expires_at)
    .bind(now)
    .fetch_optional(pool)
    .await?;

    Ok(account)
}

/// 根据提供商用户ID查找OAuth账户
pub async fn find_oauth_account_by_provider_user_id(
    pool: &PgPool,
    provider_id: &str,
    provider_user_id: &str,
) -> Result<Option<UserOAuthAccount>> {
    let account = sqlx::query_as::<_, UserOAuthAccount>(
        "SELECT id, user_id, provider_id, provider_user_id, provider_username,
                provider_email, access_token, refresh_token, token_expires_at,
                linked_at, last_login_at
         FROM user_oauth_accounts
         WHERE provider_id = $1 AND provider_user_id = $2",
    )
    .bind(provider_id)
    .bind(provider_user_id)
    .fetch_optional(pool)
    .await?;

    Ok(account)
}

/// 获取用户的所有OAuth账户
pub async fn get_user_oauth_accounts(
    pool: &PgPool,
    user_id: &str,
) -> Result<Vec<UserOAuthAccount>> {
    let accounts = sqlx::query_as::<_, UserOAuthAccount>(
        "SELECT id, user_id, provider_id, provider_user_id, provider_username,
                provider_email, access_token, refresh_token, token_expires_at,
                linked_at, last_login_at
         FROM user_oauth_accounts
         WHERE user_id = $1
         ORDER BY linked_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(accounts)
}

/// 取消关联OAuth账户
pub async fn unlink_oauth_account(pool: &PgPool, user_id: &str, provider_id: &str) -> Result<bool> {
    let result = sqlx::query(
        "DELETE FROM user_oauth_accounts WHERE user_id = $1 AND provider_id = $2",
    )
    .bind(user_id)
    .bind(provider_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// 获取OAuth账户的提供商信息
pub async fn get_oauth_account_with_provider(
    pool: &PgPool,
    account_id: &str,
) -> Result<Option<(UserOAuthAccount, OAuthProvider)>> {
    let result = sqlx::query(
        r#"
        SELECT
            uoa.id, uoa.user_id, uoa.provider_id, uoa.provider_user_id, uoa.provider_username,
            uoa.provider_email, uoa.access_token, uoa.refresh_token, uoa.token_expires_at,
            uoa.linked_at, uoa.last_login_at,
            op.name as provider_name, op.client_id, op.client_secret, op.authorization_url,
            op.token_url, op.user_info_url, op.scope, op.redirect_url, op.active,
            op.created_at as provider_created_at, op.updated_at as provider_updated_at
        FROM user_oauth_accounts uoa
        INNER JOIN oauth_providers op ON uoa.provider_id = op.id
        WHERE uoa.id = $1 AND op.active = TRUE
        "#,
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;

    match result {
        Some(row) => {
            let provider_id: String = row.get("provider_id");
            let account = UserOAuthAccount {
                id: row.get("id"),
                user_id: row.get("user_id"),
                provider_id: provider_id.clone(),
                provider_user_id: row.get("provider_user_id"),
                provider_username: row.get("provider_username"),
                provider_email: row.get("provider_email"),
                access_token: row.get("access_token"),
                refresh_token: row.get("refresh_token"),
                token_expires_at: row.get("token_expires_at"),
                linked_at: row.get("linked_at"),
                last_login_at: row.get("last_login_at"),
            };

            let provider = OAuthProvider {
                id: provider_id,
                name: row.get("provider_name"),
                client_id: row.get("client_id"),
                client_secret: row.get("client_secret"),
                authorization_url: row.get("authorization_url"),
                token_url: row.get("token_url"),
                user_info_url: row.get("user_info_url"),
                scope: row.get("scope"),
                redirect_url: row.get("redirect_url"),
                active: row.get("active"),
                created_at: row.get("provider_created_at"),
                updated_at: row.get("provider_updated_at"),
            };

            Ok(Some((account, provider)))
        }
        None => Ok(None),
    }
}

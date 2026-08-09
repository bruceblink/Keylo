use anyhow::Result;
use bcrypt::{hash, DEFAULT_COST};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::models::{
    authorization_code_hash, browser_session_hash, CreateOidcClientRequest, OidcAuthorizationCode,
    OidcBrowserSession, OidcClient, UpdateOidcClientRequest, OIDC_CLIENT_SCOPE_ORGANIZATION,
    OIDC_CLIENT_SCOPE_PLATFORM,
};

#[derive(Debug, Clone)]
pub struct OidcClientCredentialContext {
    pub client_type: String,
    pub client_secret_hash: Option<String>,
    pub active: bool,
    pub scope_kind: String,
    pub organization_id: Option<String>,
}

/// Lock a live organization before a relying party becomes tenant-owned.
async fn lock_active_oidc_client_organization(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &str,
) -> Result<()> {
    let status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM organizations WHERE id = $1 FOR UPDATE",
    )
    .bind(organization_id)
    .fetch_optional(&mut **transaction)
    .await?;
    if status.as_deref() != Some("active") {
        anyhow::bail!("organization_oidc_client_context_inactive");
    }
    Ok(())
}

/// Persist a validated OIDC relying-party registration without ever storing its secret in plaintext.
pub async fn create_oidc_client(
    pool: &PgPool,
    request: &CreateOidcClientRequest,
) -> Result<OidcClient> {
    create_oidc_client_with_scope(pool, request, None, None).await
}

/// Create a tenant client only while the delegated manager remains live and scoped.
pub async fn create_oidc_client_as_organization_manager(
    pool: &PgPool,
    organization_id: &str,
    actor_principal_id: &str,
    request: &CreateOidcClientRequest,
) -> Result<OidcClient> {
    create_oidc_client_with_scope(
        pool,
        request,
        Some(organization_id),
        Some(actor_principal_id),
    )
    .await
}

/// Persist a validated client with an immutable platform or organization scope.
async fn create_oidc_client_with_scope(
    pool: &PgPool,
    request: &CreateOidcClientRequest,
    organization_id: Option<&str>,
    actor_principal_id: Option<&str>,
) -> Result<OidcClient> {
    let secret_hash = request
        .client_secret
        .as_deref()
        .map(|secret| hash(secret, DEFAULT_COST))
        .transpose()?;
    let now = chrono::Local::now().naive_utc();
    let grant_types = request
        .grant_types
        .clone()
        .unwrap_or_else(|| vec!["authorization_code".to_string()]);
    let scopes = request.scopes.clone().unwrap_or_else(|| {
        vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ]
    });
    let scope_kind = if organization_id.is_some() {
        OIDC_CLIENT_SCOPE_ORGANIZATION
    } else {
        OIDC_CLIENT_SCOPE_PLATFORM
    };
    let mut transaction = pool.begin().await?;
    if let Some(organization_id) = organization_id {
        if let Some(actor_principal_id) = actor_principal_id {
            crate::db::organization::lock_active_organization_manager(
                &mut transaction,
                organization_id,
                actor_principal_id,
            )
            .await?;
        } else {
            lock_active_oidc_client_organization(&mut transaction, organization_id).await?;
        }
    }
    let client = sqlx::query_as::<_, OidcClient>(
        r#"
        INSERT INTO oidc_clients
            (id, client_id, client_secret_hash, name, description, client_type,
             redirect_uris, grant_types, scopes, scope_kind, organization_id,
             created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)
        RETURNING id, client_id, name, description, client_type, redirect_uris,
                  grant_types, scopes, active, scope_kind, organization_id,
                  created_at, updated_at
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&request.client_id)
    .bind(secret_hash)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&request.client_type)
    .bind(&request.redirect_uris)
    .bind(grant_types)
    .bind(scopes)
    .bind(scope_kind)
    .bind(organization_id)
    .bind(now)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(client)
}

/// Platform administration never lists tenant-owned relying parties implicitly.
pub async fn list_oidc_clients(pool: &PgPool) -> Result<Vec<OidcClient>> {
    Ok(sqlx::query_as::<_, OidcClient>(
        "SELECT id, client_id, name, description, client_type, redirect_uris, grant_types, scopes, active, scope_kind, organization_id, created_at, updated_at FROM oidc_clients WHERE scope_kind = 'platform' AND organization_id IS NULL ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?)
}

/// Return a bounded page of platform-scoped clients and whether another page exists.
pub async fn list_oidc_clients_page(
    pool: &PgPool,
    limit: i64,
    offset: i64,
) -> Result<(Vec<OidcClient>, bool)> {
    let limit = limit.clamp(1, 200);
    let offset = offset.max(0);
    let mut clients = sqlx::query_as::<_, OidcClient>(
        "SELECT id, client_id, name, description, client_type, redirect_uris, grant_types, scopes, active, scope_kind, organization_id, created_at, updated_at FROM oidc_clients WHERE scope_kind = 'platform' AND organization_id IS NULL ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit + 1)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    let has_more = clients.len() > limit as usize;
    if has_more {
        clients.truncate(limit as usize);
    }
    Ok((clients, has_more))
}

/// Public protocol lookup uses globally unique client_id but preserves stored scope.
pub async fn get_oidc_client(pool: &PgPool, client_id: &str) -> Result<Option<OidcClient>> {
    Ok(sqlx::query_as::<_, OidcClient>("SELECT id, client_id, name, description, client_type, redirect_uris, grant_types, scopes, active, scope_kind, organization_id, created_at, updated_at FROM oidc_clients WHERE client_id = $1")
        .bind(client_id).fetch_optional(pool).await?)
}

pub async fn get_platform_oidc_client(
    pool: &PgPool,
    client_id: &str,
) -> Result<Option<OidcClient>> {
    Ok(sqlx::query_as::<_, OidcClient>(
        "SELECT id, client_id, name, description, client_type, redirect_uris, grant_types, scopes, active, scope_kind, organization_id, created_at, updated_at FROM oidc_clients WHERE client_id = $1 AND scope_kind = 'platform' AND organization_id IS NULL",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn list_oidc_clients_in_organization(
    pool: &PgPool,
    organization_id: &str,
) -> Result<Vec<OidcClient>> {
    Ok(sqlx::query_as::<_, OidcClient>(
        "SELECT id, client_id, name, description, client_type, redirect_uris, grant_types, scopes, active, scope_kind, organization_id, created_at, updated_at FROM oidc_clients WHERE organization_id = $1 AND scope_kind = 'organization' ORDER BY created_at DESC",
    )
    .bind(organization_id)
    .fetch_all(pool)
    .await?)
}

/// Return a bounded page of clients owned by one organization.
pub async fn list_oidc_clients_in_organization_page(
    pool: &PgPool,
    organization_id: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<OidcClient>, bool)> {
    let limit = limit.clamp(1, 200);
    let offset = offset.max(0);
    let mut clients = sqlx::query_as::<_, OidcClient>(
        "SELECT id, client_id, name, description, client_type, redirect_uris, grant_types, scopes, active, scope_kind, organization_id, created_at, updated_at FROM oidc_clients WHERE organization_id = $1 AND scope_kind = 'organization' ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3",
    )
    .bind(organization_id)
    .bind(limit + 1)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    let has_more = clients.len() > limit as usize;
    if has_more {
        clients.truncate(limit as usize);
    }
    Ok((clients, has_more))
}

pub async fn get_oidc_client_in_organization(
    pool: &PgPool,
    organization_id: &str,
    client_id: &str,
) -> Result<Option<OidcClient>> {
    Ok(sqlx::query_as::<_, OidcClient>(
        "SELECT id, client_id, name, description, client_type, redirect_uris, grant_types, scopes, active, scope_kind, organization_id, created_at, updated_at FROM oidc_clients WHERE client_id = $1 AND organization_id = $2 AND scope_kind = 'organization'",
    )
    .bind(client_id)
    .bind(organization_id)
    .fetch_optional(pool)
    .await?)
}

/// Return only the authentication material required by the token endpoint.
pub async fn get_oidc_client_secret_hash(
    pool: &PgPool,
    client_id: &str,
) -> Result<Option<OidcClientCredentialContext>> {
    let row = sqlx::query(
        "SELECT client_type, client_secret_hash, active, scope_kind, organization_id FROM oidc_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| OidcClientCredentialContext {
        client_type: row.get("client_type"),
        client_secret_hash: row.get("client_secret_hash"),
        active: row.get("active"),
        scope_kind: row.get("scope_kind"),
        organization_id: row.get("organization_id"),
    }))
}

pub async fn get_active_authorization_code(
    pool: &PgPool,
    raw_code: &str,
) -> Result<Option<OidcAuthorizationCode>> {
    let row = sqlx::query_as::<_, (String, Option<String>, String, String, Vec<String>, Option<String>, String, i64)>(
        "SELECT client_id, organization_id, user_id, redirect_uri, scopes, nonce, code_challenge, extract(epoch from expires_at)::bigint FROM oidc_authorization_codes WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > NOW()",
    ).bind(authorization_code_hash(raw_code)).fetch_optional(pool).await?;
    Ok(row.map(
        |(
            client_id,
            organization_id,
            user_id,
            redirect_uri,
            scopes,
            nonce,
            code_challenge,
            expires_at,
        )| {
            OidcAuthorizationCode {
                client_id,
                organization_id,
                user_id,
                redirect_uri,
                scopes,
                nonce,
                code_challenge,
                expires_at,
            }
        },
    ))
}

/// Update a relying-party registration and remove pending codes when its grant boundary changes.
///
/// Audit and code invalidation share the transaction with the metadata update so an old code
/// cannot survive a disabled client or a changed redirect/scope/grant policy.
pub async fn update_oidc_client(
    pool: &PgPool,
    client_id: &str,
    request: &UpdateOidcClientRequest,
    actor: Option<&str>,
) -> Result<Option<OidcClient>> {
    update_oidc_client_scoped(pool, client_id, None, None, request, actor).await
}

/// Update one organization client only after locking the caller's live manager membership.
pub async fn update_oidc_client_as_organization_manager(
    pool: &PgPool,
    organization_id: &str,
    actor_principal_id: &str,
    client_id: &str,
    request: &UpdateOidcClientRequest,
    actor: Option<&str>,
) -> Result<Option<OidcClient>> {
    update_oidc_client_scoped(
        pool,
        client_id,
        Some(organization_id),
        Some(actor_principal_id),
        request,
        actor,
    )
    .await
}

/// Update metadata within one immutable client scope and invalidate pending codes atomically.
async fn update_oidc_client_scoped(
    pool: &PgPool,
    client_id: &str,
    organization_id: Option<&str>,
    actor_principal_id: Option<&str>,
    request: &UpdateOidcClientRequest,
    actor: Option<&str>,
) -> Result<Option<OidcClient>> {
    let now = chrono::Local::now().naive_utc();
    let mut transaction = pool.begin().await?;
    if let (Some(organization_id), Some(actor_principal_id)) = (organization_id, actor_principal_id)
    {
        crate::db::organization::lock_active_organization_manager(
            &mut transaction,
            organization_id,
            actor_principal_id,
        )
        .await?;
    }
    let previous = sqlx::query_as::<_, OidcClient>(
        "SELECT id, client_id, name, description, client_type, redirect_uris, grant_types, scopes, active, scope_kind, organization_id, created_at, updated_at FROM oidc_clients WHERE client_id = $1 AND organization_id IS NOT DISTINCT FROM $2::TEXT FOR UPDATE",
    )
    .bind(client_id)
    .bind(organization_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(previous) = previous else {
        transaction.commit().await?;
        return Ok(None);
    };
    let client = sqlx::query_as::<_, OidcClient>("UPDATE oidc_clients SET name = COALESCE($2, name), description = COALESCE($3, description), redirect_uris = COALESCE($4, redirect_uris), grant_types = COALESCE($5, grant_types), scopes = COALESCE($6, scopes), active = COALESCE($7, active), updated_at = $8 WHERE client_id = $1 AND organization_id IS NOT DISTINCT FROM $9::TEXT RETURNING id, client_id, name, description, client_type, redirect_uris, grant_types, scopes, active, scope_kind, organization_id, created_at, updated_at")
        .bind(client_id).bind(&request.name).bind(&request.description).bind(&request.redirect_uris).bind(&request.grant_types).bind(&request.scopes).bind(request.active).bind(now).bind(organization_id).fetch_one(&mut *transaction).await?;
    let trust_boundary_changed = previous.active
        && (!client.active
            || previous.redirect_uris != client.redirect_uris
            || previous.grant_types != client.grant_types
            || previous.scopes != client.scopes);
    if trust_boundary_changed {
        let invalidated_authorization_codes = sqlx::query(
            "DELETE FROM oidc_authorization_codes WHERE client_id = $1 AND consumed_at IS NULL",
        )
        .bind(client_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let event_type = if client.active {
            "oidc_client.reconfigured"
        } else {
            "oidc_client.disabled"
        };
        sqlx::query(
            "INSERT INTO audit_logs (id, event_type, actor, detail) VALUES ($1, $2, $3, $4)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(event_type)
        .bind(actor)
        .bind(format!(
            "client_id={}; organization_id={}; invalidated_authorization_codes={}",
            client_id,
            organization_id.unwrap_or(""),
            invalidated_authorization_codes
        ))
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(Some(client))
}

/// Rotate only confidential-client credentials; public clients never own a reusable secret.
pub async fn rotate_oidc_client_secret(
    pool: &PgPool,
    client_id: &str,
    new_secret: &str,
) -> Result<bool> {
    rotate_oidc_client_secret_scoped(pool, client_id, new_secret, None, None).await
}

pub async fn rotate_oidc_client_secret_as_organization_manager(
    pool: &PgPool,
    organization_id: &str,
    actor_principal_id: &str,
    client_id: &str,
    new_secret: &str,
) -> Result<bool> {
    rotate_oidc_client_secret_scoped(
        pool,
        client_id,
        new_secret,
        Some(organization_id),
        Some(actor_principal_id),
    )
    .await
}

/// Rotate credentials inside the same immutable scope and invalidate pending codes.
async fn rotate_oidc_client_secret_scoped(
    pool: &PgPool,
    client_id: &str,
    new_secret: &str,
    organization_id: Option<&str>,
    actor_principal_id: Option<&str>,
) -> Result<bool> {
    let secret_hash = hash(new_secret, DEFAULT_COST)?;
    let mut transaction = pool.begin().await?;
    if let (Some(organization_id), Some(actor_principal_id)) = (organization_id, actor_principal_id)
    {
        crate::db::organization::lock_active_organization_manager(
            &mut transaction,
            organization_id,
            actor_principal_id,
        )
        .await?;
    }
    let result = sqlx::query(
        "UPDATE oidc_clients SET client_secret_hash = $2, updated_at = NOW() WHERE client_id = $1 AND organization_id IS NOT DISTINCT FROM $3::TEXT AND client_type = 'confidential' AND active = TRUE",
    )
    .bind(client_id)
    .bind(secret_hash)
    .bind(organization_id)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() > 0 {
        sqlx::query(
            "DELETE FROM oidc_authorization_codes WHERE client_id = $1 AND organization_id IS NOT DISTINCT FROM $2::TEXT AND consumed_at IS NULL",
        )
        .bind(client_id)
        .bind(organization_id)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(result.rows_affected() > 0)
}

/// Store an authorization code as a hash; the raw value is only ever returned to its redirect URI.
pub async fn create_authorization_code(
    pool: &PgPool,
    raw_code: &str,
    authorization: &OidcAuthorizationCode,
) -> Result<()> {
    let result = sqlx::query(
        r#"
        INSERT INTO oidc_authorization_codes
            (id, code_hash, client_id, organization_id, user_id, redirect_uri,
             scopes, nonce, code_challenge, code_challenge_method, expires_at)
        SELECT $1, $2, client.client_id, client.organization_id, user_account.id,
               $6, $7, $8, $9, 'S256', to_timestamp($10)
        FROM oidc_clients AS client
        INNER JOIN users AS user_account ON user_account.id = $5 AND user_account.active = TRUE
        INNER JOIN principals AS principal
            ON principal.principal_type = 'user'
           AND principal.ref_id = user_account.id
           AND principal.active = TRUE
        WHERE client.client_id = $3
          AND client.active = TRUE
          AND client.organization_id IS NOT DISTINCT FROM $4::TEXT
          AND (
              (client.scope_kind = 'platform' AND client.organization_id IS NULL)
              OR (
                  client.scope_kind = 'organization'
                  AND client.organization_id IS NOT NULL
                  AND EXISTS (
                      SELECT 1
                      FROM organizations AS organization
                      INNER JOIN organization_memberships AS membership
                          ON membership.organization_id = organization.id
                         AND membership.principal_id = principal.id
                      WHERE organization.id = client.organization_id
                        AND organization.status = 'active'
                        AND membership.status = 'active'
                  )
              )
          )
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(authorization_code_hash(raw_code))
    .bind(&authorization.client_id)
    .bind(&authorization.organization_id)
    .bind(&authorization.user_id)
    .bind(&authorization.redirect_uri)
    .bind(&authorization.scopes)
    .bind(&authorization.nonce)
    .bind(&authorization.code_challenge)
    .bind(authorization.expires_at)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        anyhow::bail!("oidc_client_user_context_inactive");
    }
    Ok(())
}

/// Atomically mark a valid authorization code as consumed and return its immutable grant context.
pub async fn consume_authorization_code(
    pool: &PgPool,
    raw_code: &str,
) -> Result<Option<OidcAuthorizationCode>> {
    let row = sqlx::query_as::<_, (String, Option<String>, String, String, Vec<String>, Option<String>, String, i64)>(
        "UPDATE oidc_authorization_codes SET consumed_at = NOW() WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > NOW() RETURNING client_id, organization_id, user_id, redirect_uri, scopes, nonce, code_challenge, extract(epoch from expires_at)::bigint",
    )
    .bind(authorization_code_hash(raw_code))
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(
            client_id,
            organization_id,
            user_id,
            redirect_uri,
            scopes,
            nonce,
            code_challenge,
            expires_at,
        )| {
            OidcAuthorizationCode {
                client_id,
                organization_id,
                user_id,
                redirect_uri,
                scopes,
                nonce,
                code_challenge,
                expires_at,
            }
        },
    ))
}

/// Atomically consume a code only while its exact client and user tenant context remains live.
pub async fn consume_authorization_code_for_client(
    pool: &PgPool,
    raw_code: &str,
    expected_client_id: &str,
    expected_organization_id: Option<&str>,
) -> Result<Option<OidcAuthorizationCode>> {
    let row = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            String,
            String,
            Vec<String>,
            Option<String>,
            String,
            i64,
        ),
    >(
        r#"
        UPDATE oidc_authorization_codes AS auth_code
        SET consumed_at = NOW()
        FROM oidc_clients AS client, users AS user_account, principals AS principal
        WHERE auth_code.code_hash = $1
          AND auth_code.consumed_at IS NULL
          AND auth_code.expires_at > NOW()
          AND auth_code.client_id = $2
          AND auth_code.organization_id IS NOT DISTINCT FROM $3::TEXT
          AND client.client_id = auth_code.client_id
          AND client.organization_id IS NOT DISTINCT FROM auth_code.organization_id
          AND client.active = TRUE
          AND user_account.id = auth_code.user_id
          AND user_account.active = TRUE
          AND principal.principal_type = 'user'
          AND principal.ref_id = user_account.id
          AND principal.active = TRUE
          AND (
              (client.scope_kind = 'platform' AND client.organization_id IS NULL)
              OR (
                  client.scope_kind = 'organization'
                  AND client.organization_id IS NOT NULL
                  AND EXISTS (
                      SELECT 1
                      FROM organizations AS organization
                      INNER JOIN organization_memberships AS membership
                          ON membership.organization_id = organization.id
                         AND membership.principal_id = principal.id
                      WHERE organization.id = client.organization_id
                        AND organization.status = 'active'
                        AND membership.status = 'active'
                  )
              )
          )
        RETURNING auth_code.client_id, auth_code.organization_id,
                  auth_code.user_id, auth_code.redirect_uri,
                  auth_code.scopes, auth_code.nonce,
                  auth_code.code_challenge,
                  extract(epoch from auth_code.expires_at)::bigint
        "#,
    )
    .bind(authorization_code_hash(raw_code))
    .bind(expected_client_id)
    .bind(expected_organization_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(
            client_id,
            organization_id,
            user_id,
            redirect_uri,
            scopes,
            nonce,
            code_challenge,
            expires_at,
        )| {
            OidcAuthorizationCode {
                client_id,
                organization_id,
                user_id,
                redirect_uri,
                scopes,
                nonce,
                code_challenge,
                expires_at,
            }
        },
    ))
}

/// Check a public relying-party lookup without exposing a disabled tenant as usable.
pub async fn oidc_client_context_is_active(pool: &PgPool, client_id: &str) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM oidc_clients AS client
            LEFT JOIN organizations AS organization ON organization.id = client.organization_id
            WHERE client.client_id = $1
              AND client.active = TRUE
              AND (
                  (client.scope_kind = 'platform' AND client.organization_id IS NULL)
                  OR (
                      client.scope_kind = 'organization'
                      AND client.organization_id IS NOT NULL
                      AND organization.status = 'active'
                  )
              )
        )
        "#,
    )
    .bind(client_id)
    .fetch_one(pool)
    .await?)
}

/// Recheck exact client scope plus the human Principal and active membership.
pub async fn oidc_client_user_context_is_active(
    pool: &PgPool,
    client_id: &str,
    user_id: &str,
    expected_organization_id: Option<&str>,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM oidc_clients AS client
            INNER JOIN users AS user_account ON user_account.id = $2 AND user_account.active = TRUE
            INNER JOIN principals AS principal
                ON principal.principal_type = 'user'
               AND principal.ref_id = user_account.id
               AND principal.active = TRUE
            WHERE client.client_id = $1
              AND client.active = TRUE
              AND client.organization_id IS NOT DISTINCT FROM $3::TEXT
              AND (
                  (client.scope_kind = 'platform' AND client.organization_id IS NULL)
                  OR (
                      client.scope_kind = 'organization'
                      AND client.organization_id IS NOT NULL
                      AND EXISTS (
                          SELECT 1
                          FROM organizations AS organization
                          INNER JOIN organization_memberships AS membership
                              ON membership.organization_id = organization.id
                             AND membership.principal_id = principal.id
                          WHERE organization.id = client.organization_id
                            AND organization.status = 'active'
                            AND membership.status = 'active'
                      )
                  )
              )
        )
        "#,
    )
    .bind(client_id)
    .bind(user_id)
    .bind(expected_organization_id)
    .fetch_one(pool)
    .await?)
}

/// Create an opaque browser session with a hash-only database representation.
pub async fn create_browser_session(
    pool: &PgPool,
    raw_session: &str,
    session: &OidcBrowserSession,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO oidc_browser_sessions (id, session_hash, user_id, expires_at) VALUES ($1,$2,$3,to_timestamp($4))",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(browser_session_hash(raw_session))
    .bind(&session.user_id)
    .bind(session.expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Resolve an active browser cookie and touch it without extending its absolute expiry.
pub async fn resolve_browser_session(
    pool: &PgPool,
    raw_session: &str,
) -> Result<Option<OidcBrowserSession>> {
    let row = sqlx::query_as::<_, (String, i64)>(
        "UPDATE oidc_browser_sessions AS session
         SET last_seen_at = NOW()
         FROM users
         WHERE session.session_hash = $1
           AND session.revoked_at IS NULL
           AND session.expires_at > NOW()
           AND users.id = session.user_id
           AND users.active = TRUE
         RETURNING session.user_id, extract(epoch from session.expires_at)::bigint",
    )
    .bind(browser_session_hash(raw_session))
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(user_id, expires_at)| OidcBrowserSession {
        user_id,
        expires_at,
    }))
}

/// Revoke a browser session by its opaque cookie value; callers never expose the stored hash.
pub async fn revoke_browser_session(pool: &PgPool, raw_session: &str) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE oidc_browser_sessions SET revoked_at = NOW() WHERE session_hash = $1 AND revoked_at IS NULL",
    )
    .bind(browser_session_hash(raw_session))
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

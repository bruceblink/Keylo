use axum::{
    extract::{OriginalUri, Query, State},
    http::{header::AUTHORIZATION, HeaderMap},
    response::Json,
    routing::{get, post},
    Router,
};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use serde_json::json;

use crate::{
    errors::AuthError,
    models::{
        AuthorizeBatchCheckRequest, AuthorizeBatchCheckResponse, AuthorizeCheckRequest,
        AuthorizeCheckResponse, Claims, Principal, PrincipalEffectivePermissionsResponse,
        ResolvedResourcePermissionTarget, ResourceTreeQuery,
    },
    state::AppState,
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum AuthorizationTargetKind {
    Permission,
    Resource { organization_id: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedAuthorizationTarget {
    permission_name: Option<String>,
    resource_id: Option<String>,
    kind: AuthorizationTargetKind,
}

/// Represents the live principal and its one signed authorization boundary.
///
/// Human access tokens and service tokens use different claim formats, but the
/// authorization endpoints must make the same scope decision for both.
struct AuthorizationIdentity {
    principal: Principal,
    organization_id: Option<String>,
    machine_credential_key_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AuthorizationRoleScope {
    Platform,
    Organization(String),
    CrossOrganization,
}

impl AuthorizationTargetKind {
    /// Selects the only role scope allowed for the authenticated target.
    ///
    /// Direct permission checks follow the signed organization context. A
    /// concrete platform resource remains platform-scoped even when an
    /// internal employee carries a live organization context; a tenant
    /// resource must match that context exactly.
    fn role_scope(&self, organization_id: Option<&str>) -> AuthorizationRoleScope {
        match self {
            Self::Permission => organization_id
                .map_or(AuthorizationRoleScope::Platform, |organization_id| {
                    AuthorizationRoleScope::Organization(organization_id.to_string())
                }),
            Self::Resource {
                organization_id: Some(resource_organization_id),
            } => match organization_id {
                Some(context_organization_id)
                    if context_organization_id == resource_organization_id =>
                {
                    AuthorizationRoleScope::Organization(resource_organization_id.clone())
                }
                _ => AuthorizationRoleScope::CrossOrganization,
            },
            Self::Resource {
                organization_id: None,
            } => AuthorizationRoleScope::Platform,
        }
    }
}

pub fn authorization_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/authorize/check", post(authorize_check))
        .route("/v1/authorize/batch-check", post(authorize_batch_check))
        .route(
            "/v1/principals/me/effective-permissions",
            get(my_effective_permissions),
        )
        .route("/v1/principals/me/resource-tree", get(my_resource_tree))
}

async fn principal_from_bearer(
    state: &AppState,
    token: &str,
) -> Result<AuthorizationIdentity, AuthError> {
    if let Ok(claims) = state.jwt_keys.decode_token(token) {
        if claims.token_type == "access" {
            if let Some(db) = &state.db {
                if crate::db::is_token_blacklisted(db, token)
                    .await
                    .map_err(|_| AuthError::DatabaseError("Token validation failed".to_string()))?
                {
                    return Err(AuthError::InvalidToken);
                }
            }

            let principal = resolve_access_principal(state, &claims).await?;
            return Ok(AuthorizationIdentity {
                principal,
                organization_id: claims.organization_id,
                machine_credential_key_id: None,
            });
        }
    }

    let service_claims = state.jwt_keys.decode_service_token(token)?;
    if service_claims.token_type != "service_access" {
        return Err(AuthError::TokenTypeInvalid);
    }
    if service_claims.aud != "admin-backend" && service_claims.aud != "*" {
        return Err(AuthError::InvalidAudience);
    }
    if let Some(db) = &state.db {
        if crate::db::is_token_blacklisted(db, token)
            .await
            .map_err(|_| AuthError::DatabaseError("Token validation failed".to_string()))?
        {
            return Err(AuthError::InvalidToken);
        }
    }

    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let service_id = service_claims
        .sub
        .strip_prefix("service:")
        .ok_or(AuthError::InvalidToken)?;
    if service_claims.principal_type.as_deref() != Some("service") {
        return Err(AuthError::InvalidToken);
    }
    let principal_id = service_claims
        .principal_id
        .as_deref()
        .ok_or(AuthError::InvalidToken)?;
    let principal = crate::db::get_principal_by_id(db, principal_id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        .ok_or(AuthError::Forbidden)?;

    if !principal.active {
        return Err(AuthError::Forbidden);
    }

    let live = crate::db::service::service_token_context_is_active(
        db,
        service_id,
        Some(principal_id),
        service_claims.organization_id.as_deref(),
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    if !live {
        return Err(AuthError::Forbidden);
    }

    Ok(AuthorizationIdentity {
        principal,
        organization_id: service_claims.organization_id,
        machine_credential_key_id: None,
    })
}

/// Authenticates a direct machine call only for the explicit authorization APIs.
///
/// A MachineCredential is a bounded capability, not a replacement for general
/// bearer authentication. The database verifier rechecks scope, audience,
/// Principal state, and organization membership before returning this identity.
async fn principal_from_api_key(
    state: &AppState,
    raw_api_key: &str,
) -> Result<AuthorizationIdentity, AuthError> {
    let db = state.db.as_deref().ok_or_else(|| {
        AuthError::DatabaseError("Database required for API key authentication".to_string())
    })?;
    let verification = crate::db::verify_machine_credential(
        db,
        raw_api_key,
        crate::models::MACHINE_AUTHORIZATION_SCOPE,
        crate::models::MACHINE_AUTHORIZATION_AUDIENCE,
    )
    .await
    .map_err(|_| AuthError::DatabaseError("API key verification failed".to_string()))?;
    let crate::db::MachineCredentialVerification::Authorized(context) = verification else {
        let _ = crate::db::create_audit_log(
            db,
            "machine.api_key.authentication_failed",
            None,
            Some("route=authorization"),
        )
        .await;
        return Err(AuthError::InvalidToken);
    };

    let credential_bucket = format!("machine-api-key:{}", context.credential.key_id);
    if !state
        .allow_auth_request_pair(
            &credential_bucket,
            state.config.auth_rate_limit_max_requests,
            "machine-api-key:authorization-global",
            state.config.auth_global_rate_limit_max_requests,
            state.config.auth_rate_limit_window_seconds,
        )
        .await
    {
        let _ = crate::db::create_audit_log(
            db,
            "machine.api_key.rate_limited",
            Some(&context.principal.id),
            Some(&format!(
                "key_id={},route=authorization",
                context.credential.key_id
            )),
        )
        .await;
        return Err(AuthError::TooManyRequests);
    }

    let _ = crate::db::create_audit_log(
        db,
        "machine.api_key.authenticated",
        Some(&context.principal.id),
        Some(&format!(
            "key_id={},principal_id={},organization_id={},route=authorization",
            context.credential.key_id,
            context.principal.id,
            context.credential.organization_id.as_deref().unwrap_or("-")
        )),
    )
    .await;
    Ok(AuthorizationIdentity {
        principal: context.principal,
        organization_id: context.credential.organization_id,
        machine_credential_key_id: Some(context.credential.key_id),
    })
}

/// Resolves the sole supported credential transport for a machine-aware route.
fn api_key_in_query(query: Option<&str>) -> bool {
    query.is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(name, _)| {
            name.eq_ignore_ascii_case("api_key") || name.eq_ignore_ascii_case("x-api-key")
        })
    })
}

async fn principal_from_authorization_headers(
    state: &AppState,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<AuthorizationIdentity, AuthError> {
    if api_key_in_query(query) {
        return Err(AuthError::InvalidToken);
    }
    let bearer = headers.get(AUTHORIZATION);
    let api_key = headers.get("x-api-key");
    match (bearer, api_key) {
        (Some(_), Some(_)) => Err(AuthError::InvalidToken),
        (Some(value), None) => {
            let value = value.to_str().map_err(|_| AuthError::InvalidToken)?;
            let token = value
                .strip_prefix("Bearer ")
                .ok_or(AuthError::InvalidToken)?;
            if token.trim().is_empty() {
                return Err(AuthError::InvalidToken);
            }
            principal_from_bearer(state, token).await
        }
        (None, Some(value)) => {
            let api_key = value.to_str().map_err(|_| AuthError::InvalidToken)?;
            principal_from_api_key(state, api_key).await
        }
        (None, None) => Err(AuthError::Unauthorized),
    }
}

async fn resolve_access_principal(
    state: &AppState,
    claims: &Claims,
) -> Result<Principal, AuthError> {
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;

    let principal = if let Some(principal_id) = claims.principal_id.as_deref() {
        crate::db::get_principal_by_id(db, principal_id)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?
    } else if let Some(user_id) = claims.uid.as_deref() {
        crate::db::ensure_user_principal(db, user_id)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?
    } else if let Some(client_id) = claims.sub.strip_prefix("client:") {
        crate::db::ensure_client_principal(db, client_id)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?
    } else {
        crate::db::get_principal_by_subject(db, &claims.sub)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?
    }
    .ok_or(AuthError::Forbidden)?;

    if !principal.active {
        return Err(AuthError::Forbidden);
    }

    Ok(principal)
}

/// Re-checks the organization claim against current lifecycle state.
///
/// Access tokens intentionally carry only the selected organization, so every
/// authorization endpoint performs this live membership check before reading
/// organization-scoped roles. A stale or revoked context is one generic
/// forbidden result rather than a tenant-existence hint.
async fn resolve_authorization_context(
    db: &sqlx::PgPool,
    principal: &Principal,
    organization_id: Option<&str>,
) -> Result<Option<String>, AuthError> {
    let Some(organization_id) = organization_id else {
        return Ok(None);
    };

    let membership =
        crate::db::get_active_organization_membership(db, organization_id, &principal.id)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    if membership.is_none() {
        let _ = crate::db::create_authorization_audit_log_in_organization(
            db,
            Some(organization_id),
            Some(&principal.id),
            "deny",
            None,
            None,
            Some("reason=organization_context_inactive"),
        )
        .await;
        return Err(AuthError::Forbidden);
    }

    Ok(Some(organization_id.to_string()))
}

/// Resolves an authorization target into its permission and optional concrete resource ID for auditing.
async fn resolve_permission_target(
    db: &sqlx::PgPool,
    request: &AuthorizeCheckRequest,
    organization_id: Option<&str>,
) -> Result<ResolvedAuthorizationTarget, AuthError> {
    if let Some(permission) = request.permission.as_deref() {
        let permission = permission.trim();
        if !permission.is_empty() {
            return Ok(ResolvedAuthorizationTarget {
                permission_name: Some(permission.to_string()),
                resource_id: None,
                kind: AuthorizationTargetKind::Permission,
            });
        }
    }

    match (
        request.app.as_deref(),
        request.resource_type.as_deref(),
        request.resource_code.as_deref(),
    ) {
        (Some(app), Some(resource_type), Some(resource_code)) => {
            crate::db::permission_for_resource(
                db,
                app,
                resource_type,
                resource_code,
                organization_id,
            )
            .await
            .map(|target| match target {
                Some(ResolvedResourcePermissionTarget {
                    permission_name,
                    resource_id,
                    organization_id,
                }) => ResolvedAuthorizationTarget {
                    permission_name: Some(permission_name),
                    resource_id: Some(resource_id),
                    kind: AuthorizationTargetKind::Resource { organization_id },
                },
                None => ResolvedAuthorizationTarget {
                    permission_name: None,
                    resource_id: None,
                    kind: AuthorizationTargetKind::Resource {
                        organization_id: None,
                    },
                },
            })
            .map_err(|e| AuthError::DatabaseError(e.to_string()))
        }
        _ => Ok(ResolvedAuthorizationTarget {
            permission_name: None,
            resource_id: None,
            kind: AuthorizationTargetKind::Permission,
        }),
    }
}

async fn check_one(
    db: &sqlx::PgPool,
    principal: &Principal,
    request: &AuthorizeCheckRequest,
    organization_id: Option<&str>,
    machine_credential_key_id: Option<&str>,
) -> Result<AuthorizeCheckResponse, AuthError> {
    let target = resolve_permission_target(db, request, organization_id).await?;
    let role_scope = target.kind.role_scope(organization_id);
    let scope_mismatch = matches!(role_scope, AuthorizationRoleScope::CrossOrganization);
    let exposed_permission = if scope_mismatch {
        None
    } else {
        target.permission_name.as_deref()
    };
    let exposed_resource_id = if scope_mismatch {
        None
    } else {
        target.resource_id.as_deref()
    };
    let (allowed, reason) = if scope_mismatch {
        (false, "permission_not_resolved")
    } else {
        match target.permission_name.as_deref() {
            Some(permission) => {
                let allowed = match &role_scope {
                    AuthorizationRoleScope::Platform => {
                        crate::db::principal_has_permission(db, &principal.id, permission).await
                    }
                    AuthorizationRoleScope::Organization(organization_id) => {
                        crate::db::principal_has_organization_permission(
                            db,
                            &principal.id,
                            organization_id,
                            permission,
                        )
                        .await
                    }
                    AuthorizationRoleScope::CrossOrganization => unreachable!(),
                }
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
                (
                    allowed,
                    if allowed {
                        "permission_granted"
                    } else {
                        "permission_not_bound"
                    },
                )
            }
            None => (false, "permission_not_resolved"),
        }
    };
    let decision = if allowed { "allow" } else { "deny" };

    let _ = crate::db::create_authorization_audit_log_in_organization(
        db,
        organization_id,
        Some(&principal.id),
        decision,
        exposed_permission,
        exposed_resource_id,
        Some(&format!(
            "reason={reason},scope={}{}",
            match role_scope {
                AuthorizationRoleScope::Platform => "platform",
                AuthorizationRoleScope::Organization(_) => "organization",
                AuthorizationRoleScope::CrossOrganization => "cross_organization",
            },
            machine_credential_key_id
                .map(|key_id| format!(",machine_key_id={key_id}"))
                .unwrap_or_default(),
        )),
    )
    .await;

    Ok(AuthorizeCheckResponse {
        allowed,
        decision: decision.to_string(),
        reason: reason.to_string(),
        principal_id: principal.id.clone(),
        matched_permission: exposed_permission.map(ToOwned::to_owned),
    })
}

async fn authorize_check(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Json(payload): Json<AuthorizeCheckRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    payload.validate().map_err(AuthError::InvalidRequest)?;
    let identity = principal_from_authorization_headers(&state, &headers, uri.query()).await?;
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let organization_id =
        resolve_authorization_context(db, &identity.principal, identity.organization_id.as_deref())
            .await?;
    let result = check_one(
        db,
        &identity.principal,
        &payload,
        organization_id.as_deref(),
        identity.machine_credential_key_id.as_deref(),
    )
    .await?;

    Ok(Json(json!({
        "success": true,
        "data": result
    })))
}

async fn authorize_batch_check(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Json(payload): Json<AuthorizeBatchCheckRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    payload.validate().map_err(AuthError::InvalidRequest)?;
    let identity = principal_from_authorization_headers(&state, &headers, uri.query()).await?;
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let organization_id =
        resolve_authorization_context(db, &identity.principal, identity.organization_id.as_deref())
            .await?;
    let mut results = Vec::with_capacity(payload.checks.len());
    for check in &payload.checks {
        results.push(
            check_one(
                db,
                &identity.principal,
                check,
                organization_id.as_deref(),
                identity.machine_credential_key_id.as_deref(),
            )
            .await?,
        );
    }

    Ok(Json(json!({
        "success": true,
        "data": AuthorizeBatchCheckResponse { results }
    })))
}

async fn my_effective_permissions(
    State(state): State<AppState>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let identity = principal_from_bearer(&state, bearer.token()).await?;
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let organization_id =
        resolve_authorization_context(db, &identity.principal, identity.organization_id.as_deref())
            .await?;
    let roles = match organization_id.as_deref() {
        Some(organization_id) => {
            crate::db::get_principal_organization_roles(db, &identity.principal.id, organization_id)
                .await
        }
        None => crate::db::get_principal_roles(db, &identity.principal.id).await,
    }
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    let permissions = match organization_id.as_deref() {
        Some(organization_id) => {
            crate::db::get_principal_organization_permissions(
                db,
                &identity.principal.id,
                organization_id,
            )
            .await
        }
        None => crate::db::get_principal_permissions(db, &identity.principal.id).await,
    }
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "data": PrincipalEffectivePermissionsResponse {
            principal: identity.principal,
            roles,
            permissions,
        }
    })))
}

async fn my_resource_tree(
    State(state): State<AppState>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    Query(query): Query<ResourceTreeQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let identity = principal_from_bearer(&state, bearer.token()).await?;
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let organization_id =
        resolve_authorization_context(db, &identity.principal, identity.organization_id.as_deref())
            .await?;
    let tree = crate::db::authorized_resources_for_principal_in_organization(
        db,
        &identity.principal.id,
        organization_id.as_deref(),
        &query.app,
        &query.resource_type,
    )
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "data": tree
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_permission_uses_live_organization_context() {
        assert_eq!(
            AuthorizationTargetKind::Permission.role_scope(Some("org-a")),
            AuthorizationRoleScope::Organization("org-a".to_string())
        );
        assert_eq!(
            AuthorizationTargetKind::Permission.role_scope(None),
            AuthorizationRoleScope::Platform
        );
    }

    #[test]
    fn resource_scope_rejects_cross_organization_access() {
        assert_eq!(
            AuthorizationTargetKind::Resource {
                organization_id: Some("org-a".to_string()),
            }
            .role_scope(Some("org-a")),
            AuthorizationRoleScope::Organization("org-a".to_string())
        );
        assert_eq!(
            AuthorizationTargetKind::Resource {
                organization_id: Some("org-a".to_string()),
            }
            .role_scope(Some("org-b")),
            AuthorizationRoleScope::CrossOrganization
        );
        assert_eq!(
            AuthorizationTargetKind::Resource {
                organization_id: Some("org-a".to_string()),
            }
            .role_scope(None),
            AuthorizationRoleScope::CrossOrganization
        );
    }

    #[test]
    fn platform_resources_remain_platform_scoped() {
        assert_eq!(
            AuthorizationTargetKind::Resource {
                organization_id: None,
            }
            .role_scope(Some("org-a")),
            AuthorizationRoleScope::Platform
        );
    }
}

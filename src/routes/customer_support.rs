use axum::{
    extract::{Path, Query, State},
    response::Json,
    routing::{delete, get, post},
    Router,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;

use crate::{
    errors::AuthError,
    models::{
        normalize_customer_support_operations, normalize_customer_support_reason, AuthBody, Claims,
        CreateCustomerSupportAccessGrantParams, CreateCustomerSupportAuditLogParams,
        CustomerSupportAccessContext, CustomerSupportAccessGrantListQuery,
        CustomerSupportAuditLogListQuery, CUSTOMER_SUPPORT_AUDIT_OPERATION_CONTEXT_ISSUED,
        CUSTOMER_SUPPORT_AUDIT_OUTCOME_ALLOW, CUSTOMER_SUPPORT_AUDIT_OUTCOME_DENY,
        CUSTOMER_SUPPORT_DENIAL_OPERATION_NOT_ALLOWED,
        CUSTOMER_SUPPORT_DENIAL_ORGANIZATION_MISMATCH,
        CUSTOMER_SUPPORT_OPERATION_AUTHORIZATION_AUDIT_READ,
        CUSTOMER_SUPPORT_OPERATION_MEMBERSHIP_READ, CUSTOMER_SUPPORT_OPERATION_ORGANIZATION_READ,
        CUSTOMER_SUPPORT_OPERATION_REFRESH_SESSION_READ, CUSTOMER_SUPPORT_OPERATION_RESOURCE_READ,
        CUSTOMER_SUPPORT_ROLE_NAME, CUSTOMER_SUPPORT_TARGET_TYPE_ACCESS_GRANT,
        CUSTOMER_SUPPORT_TARGET_TYPE_AUTHORIZATION_AUDIT_LOG,
        CUSTOMER_SUPPORT_TARGET_TYPE_MEMBERSHIP, CUSTOMER_SUPPORT_TARGET_TYPE_ORGANIZATION,
        CUSTOMER_SUPPORT_TARGET_TYPE_REFRESH_SESSION, CUSTOMER_SUPPORT_TARGET_TYPE_RESOURCE,
    },
    state::AppState,
    utils::generate_jti,
};

const CUSTOMER_SUPPORT_TOKEN_TTL_SECONDS: i64 = 300;
const CUSTOMER_SUPPORT_MAX_GRANT_LIFETIME_SECONDS: i64 = 24 * 60 * 60;
const CUSTOMER_SUPPORT_CONTEXT_DENIED_REASON: &str = "customer_support_context_denied";
const CUSTOMER_SUPPORT_READ_FAILURE_REASON: &str = "customer_support_data_read_failed";
const CUSTOMER_SUPPORT_TARGET_NOT_FOUND_REASON: &str = "customer_support_target_not_found";

/// Normal access-token endpoint that exchanges one live grant for a dedicated
/// short-lived support token. It never creates a refresh token or membership.
pub fn customer_support_context_routes() -> Router<AppState> {
    Router::new().route(
        "/v1/customer-support/context",
        post(mint_customer_support_context),
    )
}

/// Read-only routes that are mounted with customer_support_auth_middleware.
pub fn customer_support_access_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/customer-support/organizations/{organization_id}",
            get(get_customer_support_organization),
        )
        .route(
            "/v1/customer-support/organizations/{organization_id}/memberships",
            get(list_customer_support_memberships),
        )
        .route(
            "/v1/customer-support/organizations/{organization_id}/resources",
            get(list_customer_support_resources),
        )
        .route(
            "/v1/customer-support/organizations/{organization_id}/authorization-audit-logs",
            get(list_customer_support_authorization_audit_logs),
        )
        .route(
            "/v1/customer-support/organizations/{organization_id}/refresh-sessions",
            get(list_customer_support_refresh_sessions),
        )
}

/// Platform-admin grant lifecycle endpoints. Startup layers ordinary auth,
/// live admin, and platform-operator checks around this router.
pub fn customer_support_admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/admin/customer-support-grants",
            get(list_customer_support_grants).post(create_customer_support_grant),
        )
        .route(
            "/v1/admin/customer-support-audit-logs",
            get(list_customer_support_audit_logs),
        )
        .route(
            "/v1/admin/customer-support-grants/{grant_id}",
            delete(revoke_customer_support_grant),
        )
}

#[derive(Debug, Deserialize)]
struct CustomerSupportContextRequest {
    grant_id: String,
}

#[derive(Debug, Deserialize)]
struct CreateCustomerSupportGrantRequest {
    support_principal_id: String,
    organization_id: String,
    reason: String,
    operations: Vec<String>,
    /// RFC3339 is required so the client cannot silently select server-local time.
    expires_at: String,
}

#[derive(Debug, Deserialize)]
struct RevokeCustomerSupportGrantRequest {
    reason: String,
}

#[derive(Debug, Deserialize)]
struct CustomerSupportMembershipListQuery {
    status: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct CustomerSupportResourceListQuery {
    app: Option<String>,
    #[serde(rename = "type")]
    resource_type: Option<String>,
    active: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct CustomerSupportAuthorizationAuditListQuery {
    principal_id: Option<String>,
    decision: Option<String>,
    permission_name: Option<String>,
    resource_id: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct CustomerSupportRefreshSessionListQuery {
    include_revoked: Option<bool>,
    principal_id: Option<String>,
    client_id: Option<String>,
    login_ip: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

fn support_db(state: &AppState) -> Result<&sqlx::PgPool, AuthError> {
    state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))
}

fn support_db_error(error: anyhow::Error) -> AuthError {
    AuthError::DatabaseError(error.to_string())
}

fn support_request_error(message: impl Into<String>) -> AuthError {
    AuthError::InvalidRequest(message.into())
}

/// Requires the immutable facts that bind a normal user token to one Principal.
///
/// The context issuer rejects organization-scoped and machine tokens before it
/// touches a grant, preventing a selected customer context from being reused as
/// a platform-wide support credential.
fn support_context_principal_id(claims: &Claims) -> Result<&str, AuthError> {
    if claims.token_type != "access"
        || claims.principal_type.as_deref() != Some("user")
        || claims.uid.as_deref().is_none_or(str::is_empty)
        || claims.organization_id.is_some()
        || claims.customer_support_grant_id.is_some()
        || !claims.has_audience("admin-backend")
    {
        return Err(AuthError::Forbidden);
    }
    claims
        .principal_id
        .as_deref()
        .filter(|principal_id| !principal_id.is_empty())
        .ok_or(AuthError::InvalidToken)
}

/// Confirms that the signed user id and Principal id still identify the same human.
///
/// Current access tokens already carry both values, but this explicit binding
/// prevents a malformed or legacy claim pair from borrowing somebody else's
/// support grant merely because both database records are active.
async fn require_matching_human_claim_principal(
    db: &sqlx::PgPool,
    claims: &Claims,
    principal_id: &str,
) -> Result<(), AuthError> {
    let user_id = claims.uid.as_deref().ok_or(AuthError::InvalidToken)?;
    let principal = crate::db::get_principal_by_id(db, principal_id)
        .await
        .map_err(support_db_error)?
        .ok_or(AuthError::InvalidToken)?;
    if principal.principal_type != "user" || !principal.active || principal.ref_id != user_id {
        return Err(AuthError::Forbidden);
    }
    let user = crate::db::get_user_by_id(db, user_id)
        .await
        .map_err(support_db_error)?
        .ok_or(AuthError::InvalidToken)?;
    user.active.then_some(()).ok_or(AuthError::Forbidden)
}

/// Exchanges a platform-scoped human access token for a grant-bound support JWT.
///
/// The grant is read first only to locate its target organization. The live
/// context query then rechecks the role, account, organization, revocation, and
/// expiry state before signing a token whose lifetime cannot outlast the grant.
async fn mint_customer_support_context(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<CustomerSupportContextRequest>,
) -> Result<Json<AuthBody>, AuthError> {
    let principal_id = support_context_principal_id(&claims)?;
    let grant_id = payload.grant_id.trim();
    if grant_id.is_empty() {
        return Err(support_request_error("grant_id is required"));
    }
    let db = support_db(&state)?;
    require_matching_human_claim_principal(db, &claims, principal_id).await?;
    let grant = crate::db::get_customer_support_access_grant(db, grant_id)
        .await
        .map_err(support_db_error)?
        .ok_or(AuthError::Forbidden)?;
    let decision = crate::db::get_live_customer_support_access_context(
        db,
        grant_id,
        principal_id,
        &grant.grant.organization_id,
    )
    .await
    .map_err(support_db_error)?;
    if !decision.allowed {
        // The grant exists at this point, so a rejected context exchange can
        // still be attributed to the target organization without leaking it
        // to the caller through the response.
        record_customer_support_audit(
            db,
            grant_id,
            principal_id,
            &grant.grant.organization_id,
            CUSTOMER_SUPPORT_AUDIT_OPERATION_CONTEXT_ISSUED,
            &decision.reason_snapshot,
            CUSTOMER_SUPPORT_TARGET_TYPE_ACCESS_GRANT,
            Some(grant_id),
            CUSTOMER_SUPPORT_AUDIT_OUTCOME_DENY,
            decision
                .denial_reason
                .as_deref()
                .or(Some(CUSTOMER_SUPPORT_CONTEXT_DENIED_REASON)),
        )
        .await?;
        return Err(AuthError::Forbidden);
    }
    let context = decision.context.ok_or(AuthError::Forbidden)?;

    let now = Utc::now().timestamp();
    let grant_expiry = context.expires_at.and_utc().timestamp();
    let exp = (now + CUSTOMER_SUPPORT_TOKEN_TTL_SECONDS).min(grant_expiry);
    if exp <= now {
        return Err(AuthError::Forbidden);
    }
    let support_claims = Claims {
        sub: claims.sub,
        uid: claims.uid,
        principal_id: Some(context.support_principal_id.clone()),
        principal_type: Some("user".to_string()),
        organization_id: Some(context.organization_id.clone()),
        customer_support_grant_id: Some(context.grant_id.clone()),
        iss: state.config.jwt_issuer.clone(),
        aud: "admin-backend".to_string(),
        scope: context.operations,
        role: vec![CUSTOMER_SUPPORT_ROLE_NAME.to_string()],
        token_type: "customer_support_access".to_string(),
        exp,
        iat: now,
        jti: generate_jti(),
    };
    let token = state.jwt_keys.sign_token(&support_claims)?;
    // A support token is useful only when its issuance is durably recorded;
    // failing closed here prevents an unaudited cross-organization session.
    record_customer_support_audit(
        db,
        &context.grant_id,
        &context.support_principal_id,
        &context.organization_id,
        CUSTOMER_SUPPORT_AUDIT_OPERATION_CONTEXT_ISSUED,
        &context.reason,
        CUSTOMER_SUPPORT_TARGET_TYPE_ACCESS_GRANT,
        Some(&context.grant_id),
        CUSTOMER_SUPPORT_AUDIT_OUTCOME_ALLOW,
        None,
    )
    .await?;

    Ok(Json(AuthBody::new(token, None, exp - now)))
}

/// Requires a current human internal administrator plus a factor verified for this JWT.
///
/// Generic admin middleware permits machine administrators for automation. Grant
/// creation and revocation are intentionally stricter because they open a
/// temporary cross-customer investigation channel.
async fn require_human_platform_admin_with_recent_mfa(
    state: &AppState,
    claims: &Claims,
) -> Result<String, AuthError> {
    if claims.token_type != "access"
        || claims.principal_type.as_deref() != Some("user")
        || !claims.has_role("admin")
        || !claims.has_scope("admin")
        || !claims.has_audience("admin-backend")
    {
        return Err(AuthError::Forbidden);
    }
    let user_id = claims.uid.as_deref().ok_or(AuthError::InvalidToken)?;
    let principal_id = claims
        .principal_id
        .as_deref()
        .ok_or(AuthError::InvalidToken)?;
    let db = support_db(state)?;
    let principal = crate::db::get_principal_by_id(db, principal_id)
        .await
        .map_err(support_db_error)?
        .ok_or(AuthError::InvalidToken)?;
    if !principal.active || principal.principal_type != "user" || principal.ref_id != user_id {
        return Err(AuthError::Forbidden);
    }
    let user = crate::db::get_user_by_id(db, user_id)
        .await
        .map_err(support_db_error)?
        .ok_or(AuthError::InvalidToken)?;
    if !user.active || user.user_class != crate::models::USER_CLASS_INTERNAL_EMPLOYEE {
        return Err(AuthError::Forbidden);
    }
    if !crate::db::user_is_platform_admin(db, user_id)
        .await
        .map_err(support_db_error)?
    {
        return Err(AuthError::Forbidden);
    }
    let mfa_enabled = crate::db::get_totp_credential(db, user_id)
        .await
        .map_err(support_db_error)?
        .is_some_and(|credential| credential.enabled_at.is_some());
    // Match the existing sensitive-operation policy: an enrolled factor must
    // be freshly verified, while deployments that have not enrolled MFA yet
    // retain their established access behavior.
    if mfa_enabled
        && !crate::db::has_recent_mfa_verification(db, user_id, &claims.jti)
            .await
            .map_err(support_db_error)?
    {
        return Err(AuthError::Forbidden);
    }

    Ok(principal.id)
}

fn parse_customer_support_grant_expiry(value: &str) -> Result<chrono::NaiveDateTime, AuthError> {
    let expiry = DateTime::parse_from_rfc3339(value.trim())
        .map_err(|_| support_request_error("expires_at must be an RFC3339 timestamp"))?
        .with_timezone(&Utc);
    let now = Utc::now();
    if expiry <= now {
        return Err(support_request_error("expires_at must be in the future"));
    }
    if expiry > now + chrono::Duration::seconds(CUSTOMER_SUPPORT_MAX_GRANT_LIFETIME_SECONDS) {
        return Err(support_request_error(
            "expires_at exceeds the maximum customer-support grant lifetime",
        ));
    }
    Ok(expiry.naive_utc())
}

async fn list_customer_support_grants(
    State(state): State<AppState>,
    Query(query): Query<CustomerSupportAccessGrantListQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = support_db(&state)?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);
    let (grants, has_more) = crate::db::list_customer_support_access_grants_page(
        db,
        query.organization_id.as_deref(),
        query.support_principal_id.as_deref(),
        query.granted_by_principal_id.as_deref(),
        query.include_revoked.unwrap_or(false),
        limit,
        offset,
    )
    .await
    .map_err(support_db_error)?;

    Ok(Json(json!({
        "success": true,
        "data": grants,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "has_more": has_more,
            "next_offset": has_more.then_some(offset + limit),
        }
    })))
}

/// Lets platform operators inspect the immutable support trail with exact filters.
///
/// The route is platform-admin-only at startup; this function still bounds each
/// optional filter and pagination argument before the database query is issued.
async fn list_customer_support_audit_logs(
    State(state): State<AppState>,
    Query(query): Query<CustomerSupportAuditLogListQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let db = support_db(&state)?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);
    let (logs, has_more) = crate::db::list_customer_support_audit_logs_page(
        db,
        query.organization_id.as_deref(),
        query.actor_principal_id.as_deref(),
        query.grant_id.as_deref(),
        query.operation.as_deref(),
        query.outcome.as_deref(),
        limit,
        offset,
    )
    .await
    .map_err(support_db_error)?;

    Ok(Json(json!({
        "success": true,
        "data": logs,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "has_more": has_more,
            "next_offset": has_more.then_some(offset + limit),
        }
    })))
}

async fn create_customer_support_grant(
    claims: Claims,
    State(state): State<AppState>,
    Json(payload): Json<CreateCustomerSupportGrantRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let granted_by_principal_id =
        require_human_platform_admin_with_recent_mfa(&state, &claims).await?;
    let reason =
        normalize_customer_support_reason(&payload.reason).map_err(support_request_error)?;
    let operations = normalize_customer_support_operations(&payload.operations)
        .map_err(support_request_error)?;
    let expires_at = parse_customer_support_grant_expiry(&payload.expires_at)?;
    let db = support_db(&state)?;
    let grant = crate::db::create_customer_support_access_grant(
        db,
        CreateCustomerSupportAccessGrantParams {
            support_principal_id: &payload.support_principal_id,
            organization_id: &payload.organization_id,
            reason: &reason,
            granted_by_principal_id: &granted_by_principal_id,
            expires_at,
            operations: &operations,
        },
    )
    .await
    .map_err(support_db_error)?;

    Ok(Json(json!({ "success": true, "data": grant })))
}

async fn revoke_customer_support_grant(
    claims: Claims,
    State(state): State<AppState>,
    Path(grant_id): Path<String>,
    Json(payload): Json<RevokeCustomerSupportGrantRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let revoked_by_principal_id =
        require_human_platform_admin_with_recent_mfa(&state, &claims).await?;
    let reason =
        normalize_customer_support_reason(&payload.reason).map_err(support_request_error)?;
    let db = support_db(&state)?;
    let grant = crate::db::revoke_customer_support_access_grant(
        db,
        &grant_id,
        &revoked_by_principal_id,
        &reason,
    )
    .await
    .map_err(support_db_error)?
    .ok_or(AuthError::NotFound)?;

    Ok(Json(json!({ "success": true, "data": grant })))
}

/// Live-checks the signed grant before every read and writes a mandatory deny audit.
///
/// The path organization must match the JWT organization *and* the database
/// grant. This stops a holder from changing only a URL segment to inspect a
/// different customer, even when both customers have similarly named data.
async fn authorize_customer_support_read(
    state: &AppState,
    claims: &Claims,
    path_organization_id: &str,
    operation: &str,
    target_type: &str,
    target_id: Option<&str>,
) -> Result<CustomerSupportAccessContext, AuthError> {
    let db = support_db(state)?;
    let grant_id = claims
        .customer_support_grant_id
        .as_deref()
        .filter(|grant_id| !grant_id.is_empty())
        .ok_or(AuthError::InvalidToken)?;
    let principal_id = claims
        .principal_id
        .as_deref()
        .filter(|principal_id| !principal_id.is_empty())
        .ok_or(AuthError::InvalidToken)?;
    let signed_organization_id = claims
        .organization_id
        .as_deref()
        .filter(|organization_id| !organization_id.is_empty())
        .ok_or(AuthError::InvalidToken)?;
    require_matching_human_claim_principal(db, claims, principal_id).await?;

    let mut decision = crate::db::get_live_customer_support_access_context(
        db,
        grant_id,
        principal_id,
        signed_organization_id,
    )
    .await
    .map_err(support_db_error)?;
    if signed_organization_id != path_organization_id {
        decision.allowed = false;
        decision.denial_reason = Some(CUSTOMER_SUPPORT_DENIAL_ORGANIZATION_MISMATCH.to_string());
    } else if decision.allowed && !claims.has_scope(operation) {
        decision.allowed = false;
        decision.denial_reason = Some(CUSTOMER_SUPPORT_DENIAL_OPERATION_NOT_ALLOWED.to_string());
    } else if decision.allowed {
        decision = crate::db::check_customer_support_access_operation(
            db,
            grant_id,
            principal_id,
            path_organization_id,
            operation,
        )
        .await
        .map_err(support_db_error)?;
    }

    if !decision.allowed {
        record_customer_support_audit(
            db,
            grant_id,
            principal_id,
            path_organization_id,
            operation,
            &decision.reason_snapshot,
            target_type,
            target_id,
            CUSTOMER_SUPPORT_AUDIT_OUTCOME_DENY,
            decision.denial_reason.as_deref(),
        )
        .await?;
        return Err(AuthError::Forbidden);
    }

    decision.context.ok_or(AuthError::Forbidden)
}

/// Persists one support decision and turns an audit failure into a failed request.
#[allow(clippy::too_many_arguments)]
async fn record_customer_support_audit(
    db: &sqlx::PgPool,
    grant_id: &str,
    principal_id: &str,
    organization_id: &str,
    operation: &str,
    reason_snapshot: &str,
    target_type: &str,
    target_id: Option<&str>,
    outcome: &str,
    denial_reason: Option<&str>,
) -> Result<(), AuthError> {
    crate::db::create_customer_support_audit_log(
        db,
        CreateCustomerSupportAuditLogParams {
            grant_id: Some(grant_id),
            actor_principal_id: Some(principal_id),
            organization_id,
            operation,
            reason_snapshot,
            target_type,
            target_id,
            outcome,
            denial_reason,
        },
    )
    .await
    .map_err(support_db_error)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn record_customer_support_read_failure(
    state: &AppState,
    claims: &Claims,
    context: &CustomerSupportAccessContext,
    organization_id: &str,
    operation: &str,
    target_type: &str,
    target_id: Option<&str>,
    reason: &str,
) -> Result<(), AuthError> {
    let db = support_db(state)?;
    record_customer_support_audit(
        db,
        &context.grant_id,
        claims
            .principal_id
            .as_deref()
            .ok_or(AuthError::InvalidToken)?,
        organization_id,
        operation,
        &context.reason,
        target_type,
        target_id,
        CUSTOMER_SUPPORT_AUDIT_OUTCOME_DENY,
        Some(reason),
    )
    .await
}

async fn record_customer_support_read_success(
    state: &AppState,
    claims: &Claims,
    context: &CustomerSupportAccessContext,
    organization_id: &str,
    operation: &str,
    target_type: &str,
    target_id: Option<&str>,
) -> Result<(), AuthError> {
    let db = support_db(state)?;
    record_customer_support_audit(
        db,
        &context.grant_id,
        claims
            .principal_id
            .as_deref()
            .ok_or(AuthError::InvalidToken)?,
        organization_id,
        operation,
        &context.reason,
        target_type,
        target_id,
        CUSTOMER_SUPPORT_AUDIT_OUTCOME_ALLOW,
        None,
    )
    .await
}

async fn get_customer_support_organization(
    claims: Claims,
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let context = authorize_customer_support_read(
        &state,
        &claims,
        &organization_id,
        CUSTOMER_SUPPORT_OPERATION_ORGANIZATION_READ,
        CUSTOMER_SUPPORT_TARGET_TYPE_ORGANIZATION,
        Some(&organization_id),
    )
    .await?;
    let db = support_db(&state)?;
    let organization = crate::db::get_organization_by_id(db, &organization_id).await;
    let organization = match organization {
        Ok(organization) => organization,
        Err(error) => {
            record_customer_support_read_failure(
                &state,
                &claims,
                &context,
                &organization_id,
                CUSTOMER_SUPPORT_OPERATION_ORGANIZATION_READ,
                CUSTOMER_SUPPORT_TARGET_TYPE_ORGANIZATION,
                Some(&organization_id),
                CUSTOMER_SUPPORT_READ_FAILURE_REASON,
            )
            .await?;
            return Err(support_db_error(error));
        }
    };
    let Some(organization) = organization else {
        record_customer_support_read_failure(
            &state,
            &claims,
            &context,
            &organization_id,
            CUSTOMER_SUPPORT_OPERATION_ORGANIZATION_READ,
            CUSTOMER_SUPPORT_TARGET_TYPE_ORGANIZATION,
            Some(&organization_id),
            CUSTOMER_SUPPORT_TARGET_NOT_FOUND_REASON,
        )
        .await?;
        return Err(AuthError::Forbidden);
    };
    record_customer_support_read_success(
        &state,
        &claims,
        &context,
        &organization_id,
        CUSTOMER_SUPPORT_OPERATION_ORGANIZATION_READ,
        CUSTOMER_SUPPORT_TARGET_TYPE_ORGANIZATION,
        Some(&organization_id),
    )
    .await?;

    Ok(Json(json!({ "success": true, "data": organization })))
}

async fn list_customer_support_memberships(
    claims: Claims,
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    Query(query): Query<CustomerSupportMembershipListQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let context = authorize_customer_support_read(
        &state,
        &claims,
        &organization_id,
        CUSTOMER_SUPPORT_OPERATION_MEMBERSHIP_READ,
        CUSTOMER_SUPPORT_TARGET_TYPE_MEMBERSHIP,
        Some(&organization_id),
    )
    .await?;
    let db = support_db(&state)?;
    let memberships = crate::db::list_organization_memberships(
        db,
        &organization_id,
        query.status.as_deref(),
        query.limit.unwrap_or(50).clamp(1, 200),
        query.offset.unwrap_or(0).max(0),
    )
    .await;
    let memberships = match memberships {
        Ok(memberships) => memberships,
        Err(error) => {
            record_customer_support_read_failure(
                &state,
                &claims,
                &context,
                &organization_id,
                CUSTOMER_SUPPORT_OPERATION_MEMBERSHIP_READ,
                CUSTOMER_SUPPORT_TARGET_TYPE_MEMBERSHIP,
                Some(&organization_id),
                CUSTOMER_SUPPORT_READ_FAILURE_REASON,
            )
            .await?;
            return Err(support_db_error(error));
        }
    };
    record_customer_support_read_success(
        &state,
        &claims,
        &context,
        &organization_id,
        CUSTOMER_SUPPORT_OPERATION_MEMBERSHIP_READ,
        CUSTOMER_SUPPORT_TARGET_TYPE_MEMBERSHIP,
        Some(&organization_id),
    )
    .await?;

    Ok(Json(json!({ "success": true, "data": memberships })))
}

async fn list_customer_support_resources(
    claims: Claims,
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    Query(query): Query<CustomerSupportResourceListQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let context = authorize_customer_support_read(
        &state,
        &claims,
        &organization_id,
        CUSTOMER_SUPPORT_OPERATION_RESOURCE_READ,
        CUSTOMER_SUPPORT_TARGET_TYPE_RESOURCE,
        Some(&organization_id),
    )
    .await?;
    let db = support_db(&state)?;
    let resources = crate::db::list_resources_for_admin(
        db,
        Some(&organization_id),
        query.app.as_deref(),
        query.resource_type.as_deref(),
        query.active,
    )
    .await;
    let resources = match resources {
        Ok(resources) => resources,
        Err(error) => {
            record_customer_support_read_failure(
                &state,
                &claims,
                &context,
                &organization_id,
                CUSTOMER_SUPPORT_OPERATION_RESOURCE_READ,
                CUSTOMER_SUPPORT_TARGET_TYPE_RESOURCE,
                Some(&organization_id),
                CUSTOMER_SUPPORT_READ_FAILURE_REASON,
            )
            .await?;
            return Err(support_db_error(error));
        }
    };
    record_customer_support_read_success(
        &state,
        &claims,
        &context,
        &organization_id,
        CUSTOMER_SUPPORT_OPERATION_RESOURCE_READ,
        CUSTOMER_SUPPORT_TARGET_TYPE_RESOURCE,
        Some(&organization_id),
    )
    .await?;

    Ok(Json(json!({ "success": true, "data": resources })))
}

async fn list_customer_support_authorization_audit_logs(
    claims: Claims,
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    Query(query): Query<CustomerSupportAuthorizationAuditListQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let context = authorize_customer_support_read(
        &state,
        &claims,
        &organization_id,
        CUSTOMER_SUPPORT_OPERATION_AUTHORIZATION_AUDIT_READ,
        CUSTOMER_SUPPORT_TARGET_TYPE_AUTHORIZATION_AUDIT_LOG,
        Some(&organization_id),
    )
    .await?;
    let db = support_db(&state)?;
    let logs = crate::db::list_authorization_audit_logs_in_organization(
        db,
        Some(&organization_id),
        query.principal_id.as_deref(),
        query.decision.as_deref(),
        query.permission_name.as_deref(),
        query.resource_id.as_deref(),
        query.limit.unwrap_or(50).clamp(1, 200),
        query.offset.unwrap_or(0).max(0),
    )
    .await;
    let logs = match logs {
        Ok(logs) => logs,
        Err(error) => {
            record_customer_support_read_failure(
                &state,
                &claims,
                &context,
                &organization_id,
                CUSTOMER_SUPPORT_OPERATION_AUTHORIZATION_AUDIT_READ,
                CUSTOMER_SUPPORT_TARGET_TYPE_AUTHORIZATION_AUDIT_LOG,
                Some(&organization_id),
                CUSTOMER_SUPPORT_READ_FAILURE_REASON,
            )
            .await?;
            return Err(support_db_error(error));
        }
    };
    record_customer_support_read_success(
        &state,
        &claims,
        &context,
        &organization_id,
        CUSTOMER_SUPPORT_OPERATION_AUTHORIZATION_AUDIT_READ,
        CUSTOMER_SUPPORT_TARGET_TYPE_AUTHORIZATION_AUDIT_LOG,
        Some(&organization_id),
    )
    .await?;

    Ok(Json(json!({ "success": true, "data": logs })))
}

async fn list_customer_support_refresh_sessions(
    claims: Claims,
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    Query(query): Query<CustomerSupportRefreshSessionListQuery>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let context = authorize_customer_support_read(
        &state,
        &claims,
        &organization_id,
        CUSTOMER_SUPPORT_OPERATION_REFRESH_SESSION_READ,
        CUSTOMER_SUPPORT_TARGET_TYPE_REFRESH_SESSION,
        Some(&organization_id),
    )
    .await?;
    let db = support_db(&state)?;
    let sessions = crate::db::list_refresh_sessions_in_organization(
        db,
        Some(&organization_id),
        query.include_revoked.unwrap_or(false),
        query.principal_id.as_deref(),
        query.client_id.as_deref(),
        query.login_ip.as_deref(),
        query.limit.unwrap_or(50).clamp(1, 200),
        query.offset.unwrap_or(0).max(0),
    )
    .await;
    let sessions = match sessions {
        Ok(sessions) => sessions,
        Err(error) => {
            record_customer_support_read_failure(
                &state,
                &claims,
                &context,
                &organization_id,
                CUSTOMER_SUPPORT_OPERATION_REFRESH_SESSION_READ,
                CUSTOMER_SUPPORT_TARGET_TYPE_REFRESH_SESSION,
                Some(&organization_id),
                CUSTOMER_SUPPORT_READ_FAILURE_REASON,
            )
            .await?;
            return Err(support_db_error(error));
        }
    };
    record_customer_support_read_success(
        &state,
        &claims,
        &context,
        &organization_id,
        CUSTOMER_SUPPORT_OPERATION_REFRESH_SESSION_READ,
        CUSTOMER_SUPPORT_TARGET_TYPE_REFRESH_SESSION,
        Some(&organization_id),
    )
    .await?;

    Ok(Json(json!({ "success": true, "data": sessions })))
}

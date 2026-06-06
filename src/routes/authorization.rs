use axum::{
    extract::{Query, State},
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
        ResourceTreeQuery,
    },
    state::AppState,
};

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
) -> Result<(Principal, Option<Claims>), AuthError> {
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
            return Ok((principal, Some(claims)));
        }
    }

    let service_claims = state.jwt_keys.decode_service_token(token)?;
    if service_claims.token_type != "service_access" {
        return Err(AuthError::TokenTypeInvalid);
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
    let principal = if let Some(principal_id) = service_claims.principal_id.as_deref() {
        crate::db::get_principal_by_id(db, principal_id)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?
    } else if let Some(service_id) = service_claims.sub.strip_prefix("service:") {
        crate::db::get_principal_by_ref(db, "service", service_id)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?
    } else {
        None
    }
    .ok_or(AuthError::Forbidden)?;

    if !principal.active {
        return Err(AuthError::Forbidden);
    }

    Ok((principal, None))
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

async fn resolve_permission_name(
    db: &sqlx::PgPool,
    request: &AuthorizeCheckRequest,
) -> Result<Option<String>, AuthError> {
    if let Some(permission) = request.permission.as_deref() {
        let permission = permission.trim();
        if !permission.is_empty() {
            return Ok(Some(permission.to_string()));
        }
    }

    match (
        request.app.as_deref(),
        request.resource_type.as_deref(),
        request.resource_code.as_deref(),
    ) {
        (Some(app), Some(resource_type), Some(resource_code)) => {
            crate::db::permission_for_resource(db, app, resource_type, resource_code)
                .await
                .map_err(|e| AuthError::DatabaseError(e.to_string()))
        }
        _ => Ok(None),
    }
}

async fn check_one(
    db: &sqlx::PgPool,
    principal: &Principal,
    request: &AuthorizeCheckRequest,
) -> Result<AuthorizeCheckResponse, AuthError> {
    let permission_name = resolve_permission_name(db, request).await?;
    let allowed = match permission_name.as_deref() {
        Some(permission) => crate::db::principal_has_permission(db, &principal.id, permission)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?,
        None => false,
    };

    let _ = crate::db::create_authorization_audit_log(
        db,
        Some(&principal.id),
        if allowed { "allow" } else { "deny" },
        permission_name.as_deref(),
        None,
        None,
    )
    .await;

    Ok(AuthorizeCheckResponse {
        allowed,
        principal_id: principal.id.clone(),
        matched_permission: permission_name,
    })
}

async fn authorize_check(
    State(state): State<AppState>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    Json(payload): Json<AuthorizeCheckRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let (principal, _) = principal_from_bearer(&state, bearer.token()).await?;
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let result = check_one(db, &principal, &payload).await?;

    Ok(Json(json!({
        "success": true,
        "data": result
    })))
}

async fn authorize_batch_check(
    State(state): State<AppState>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    Json(payload): Json<AuthorizeBatchCheckRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let (principal, _) = principal_from_bearer(&state, bearer.token()).await?;
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let mut results = Vec::with_capacity(payload.checks.len());
    for check in &payload.checks {
        results.push(check_one(db, &principal, check).await?);
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
    let (principal, _) = principal_from_bearer(&state, bearer.token()).await?;
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let roles = crate::db::get_principal_roles(db, &principal.id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    let permissions = crate::db::get_principal_permissions(db, &principal.id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({
        "success": true,
        "data": PrincipalEffectivePermissionsResponse {
            principal,
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
    let (principal, _) = principal_from_bearer(&state, bearer.token()).await?;
    let db = state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))?;
    let tree = crate::db::authorized_resources_for_principal(
        db,
        &principal.id,
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

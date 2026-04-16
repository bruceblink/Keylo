use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::json;
use serde_json::Value;

use crate::db::user::{
    create_user, get_mapped_user_id, get_user_by_email, get_user_by_id, get_user_by_username,
    set_user_active, upsert_external_user_mapping,
};
use crate::db::{assign_role_to_user, create_audit_log, get_role_by_name, update_user};
use crate::models::{
    Claims, CreateUserRequest, ThirdPartyUserImportRequest, ThirdPartyUserImportResultItem,
};
use crate::state::AppState;
use crate::utils::ApiResponse;

/// 用户注册处理器
pub async fn register_user(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> ApiResponse {
    let db = match &state.db {
        Some(db) => db,
        None => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": "Database not available",
                })),
            ));
        }
    };

    // 验证密码长度
    if let Some(ref password) = req.password {
        if password.len() < 8 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "error": "Password must be at least 8 characters long",
                })),
            ));
        }
    }

    match create_user(db, &req.username, &req.email, req.password.as_deref()).await {
        Ok(user) => Ok(Json(json!({
            "success": true,
            "data": user,
        }))),
        Err(e) => {
            if e.to_string().contains("duplicate key") {
                Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "success": false,
                        "error": "Username or email already exists",
                    })),
                ))
            } else {
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "success": false,
                        "error": format!("Failed to create user: {}", e),
                    })),
                ))
            }
        }
    }
}

pub async fn import_third_party_users(
    State(state): State<AppState>,
    claims: Claims,
    Json(req): Json<ThirdPartyUserImportRequest>,
) -> ApiResponse {
    let db = match &state.db {
        Some(db) => db,
        None => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": "Database not available",
                })),
            ));
        }
    };

    if req.users.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "users must not be empty",
            })),
        ));
    }

    let provider = req.provider.trim().to_lowercase();
    if provider.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "provider must not be empty",
            })),
        ));
    }

    let dry_run = req.dry_run.unwrap_or(false);
    let mut results: Vec<ThirdPartyUserImportResultItem> = Vec::with_capacity(req.users.len());
    let mut created = 0;
    let mut updated = 0;
    let mut linked = 0;
    let mut failed = 0;

    for item in req.users {
        let external_user_id = item.external_user_id.trim().to_string();
        let username = item.username.trim().to_string();
        let email = item.email.trim().to_string();

        if external_user_id.is_empty() || username.is_empty() || email.is_empty() {
            failed += 1;
            results.push(ThirdPartyUserImportResultItem {
                external_user_id,
                user_id: None,
                status: "failed".to_string(),
                message: Some("external_user_id/username/email are required".to_string()),
            });
            continue;
        }

        let active = item.active.unwrap_or(true);
        if let Some(password) = item.password.as_deref() {
            if password.len() < 8 {
                failed += 1;
                results.push(ThirdPartyUserImportResultItem {
                    external_user_id,
                    user_id: None,
                    status: "failed".to_string(),
                    message: Some("password must be at least 8 characters".to_string()),
                });
                continue;
            }
        }

        let metadata_value = item
            .metadata
            .map(|value| Value::Object(value.into_iter().collect()));

        if dry_run {
            results.push(ThirdPartyUserImportResultItem {
                external_user_id,
                user_id: None,
                status: "dry_run".to_string(),
                message: Some("validated".to_string()),
            });
            continue;
        }

        let mapped_user_id = match get_mapped_user_id(db, &provider, &external_user_id).await {
            Ok(value) => value,
            Err(e) => {
                failed += 1;
                results.push(ThirdPartyUserImportResultItem {
                    external_user_id,
                    user_id: None,
                    status: "failed".to_string(),
                    message: Some(format!("failed to query mapping: {e}")),
                });
                continue;
            }
        };

        let (resolved_user, status, user_id) = if let Some(existing_user_id) = mapped_user_id {
            match get_user_by_id(db, &existing_user_id).await {
                Ok(Some(user)) => {
                    match update_user(
                        db,
                        &user.id,
                        Some(&username),
                        Some(&email),
                        item.password.as_deref(),
                        Some(active),
                    )
                    .await
                    {
                        Ok(Some(updated_user)) => {
                            updated += 1;
                            (updated_user, "updated".to_string(), Some(user.id.clone()))
                        }
                        Ok(None) => (user.clone(), "updated".to_string(), Some(user.id.clone())),
                        Err(e) => {
                            failed += 1;
                            results.push(ThirdPartyUserImportResultItem {
                                external_user_id,
                                user_id: Some(user.id.clone()),
                                status: "failed".to_string(),
                                message: Some(format!("failed to update mapped user: {e}")),
                            });
                            continue;
                        }
                    }
                }
                Ok(None) => {
                    match create_user(db, &username, &email, item.password.as_deref()).await {
                        Ok(new_user) => {
                            if !active {
                                let _ = set_user_active(db, &new_user.id, false).await;
                            }
                            created += 1;
                            (
                                new_user.clone(),
                                "created".to_string(),
                                Some(new_user.id.clone()),
                            )
                        }
                        Err(e) => {
                            failed += 1;
                            results.push(ThirdPartyUserImportResultItem {
                                external_user_id,
                                user_id: None,
                                status: "failed".to_string(),
                                message: Some(format!("failed to create remapped user: {e}")),
                            });
                            continue;
                        }
                    }
                }
                Err(e) => {
                    failed += 1;
                    results.push(ThirdPartyUserImportResultItem {
                        external_user_id,
                        user_id: None,
                        status: "failed".to_string(),
                        message: Some(format!("failed to load mapped user: {e}")),
                    });
                    continue;
                }
            }
        } else if let Ok(Some(user)) = get_user_by_email(db, &email).await {
            linked += 1;
            let _ = update_user(
                db,
                &user.id,
                Some(&username),
                Some(&email),
                item.password.as_deref(),
                Some(active),
            )
            .await;
            (user.clone(), "linked".to_string(), Some(user.id.clone()))
        } else if let Ok(Some(user)) = get_user_by_username(db, &username).await {
            linked += 1;
            let _ = update_user(
                db,
                &user.id,
                Some(&username),
                Some(&email),
                item.password.as_deref(),
                Some(active),
            )
            .await;
            (user.clone(), "linked".to_string(), Some(user.id.clone()))
        } else {
            match create_user(db, &username, &email, item.password.as_deref()).await {
                Ok(user) => {
                    if !active {
                        let _ = set_user_active(db, &user.id, false).await;
                    }
                    created += 1;
                    (user.clone(), "created".to_string(), Some(user.id.clone()))
                }
                Err(e) => {
                    failed += 1;
                    results.push(ThirdPartyUserImportResultItem {
                        external_user_id,
                        user_id: None,
                        status: "failed".to_string(),
                        message: Some(format!("failed to create user: {e}")),
                    });
                    continue;
                }
            }
        };

        if let Err(e) = upsert_external_user_mapping(
            db,
            &provider,
            &external_user_id,
            &resolved_user.id,
            metadata_value.as_ref(),
        )
        .await
        {
            failed += 1;
            results.push(ThirdPartyUserImportResultItem {
                external_user_id,
                user_id: Some(resolved_user.id),
                status: "failed".to_string(),
                message: Some(format!("failed to upsert external mapping: {e}")),
            });
            continue;
        }

        if let Some(roles) = item.roles {
            for role_name in roles {
                if let Ok(Some(role)) = get_role_by_name(db, role_name.trim()).await {
                    let _ = assign_role_to_user(db, &resolved_user.id, &role.id).await;
                }
            }
        }

        results.push(ThirdPartyUserImportResultItem {
            external_user_id,
            user_id: user_id.or_else(|| Some(resolved_user.id)),
            status,
            message: None,
        });
    }

    let _ = create_audit_log(
        db,
        "migration.third_party.users.import",
        Some(&claims.sub),
        Some(&format!(
            "provider={}, dry_run={}, total={}, created={}, updated={}, linked={}, failed={}",
            provider,
            dry_run,
            results.len(),
            created,
            updated,
            linked,
            failed
        )),
    )
    .await;

    Ok(Json(json!({
        "success": true,
        "provider": provider,
        "dry_run": dry_run,
        "summary": {
            "total": results.len(),
            "created": created,
            "updated": updated,
            "linked": linked,
            "failed": failed
        },
        "results": results
    })))
}

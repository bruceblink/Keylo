use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde_json::json;
use serde_json::Value;
use uuid::Uuid;

use crate::db::user::{
    create_user, get_mapped_user_id, get_user_by_email, get_user_by_id, get_user_by_username,
    set_user_active, upsert_external_user_mapping,
};
use crate::db::{assign_role_to_user, create_audit_log, get_role_by_name, update_user};
use crate::models::{
    Claims, CreateUserRequest, MigrationBatchJob, MigrationErrorCode, MigrationJobStatus,
    ThirdPartyJitRegisterRequest, ThirdPartyUserImportItem, ThirdPartyUserImportOutput,
    ThirdPartyUserImportRequest, ThirdPartyUserImportResultItem, ThirdPartyUserImportSummary,
};
use crate::state::AppState;
use crate::utils::{validate_password_complexity, ApiResponse};

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

    // 验证密码复杂度
    if let Some(ref password) = req.password {
        if let Err(msg) = validate_password_complexity(password) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "error": msg,
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

fn migration_error_response(
    status: StatusCode,
    error_code: MigrationErrorCode,
    message: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(json!({
            "success": false,
            "error_code": error_code,
            "error": message,
        })),
    )
}

fn map_item_error_code(e: &str) -> MigrationErrorCode {
    if e.contains("duplicate key") {
        MigrationErrorCode::Conflict
    } else {
        MigrationErrorCode::InternalError
    }
}

fn push_failed_result(
    results: &mut Vec<ThirdPartyUserImportResultItem>,
    external_user_id: String,
    user_id: Option<String>,
    error_code: MigrationErrorCode,
    message: String,
) {
    results.push(ThirdPartyUserImportResultItem {
        external_user_id,
        user_id,
        status: "failed".to_string(),
        error_code: Some(error_code),
        message: Some(message),
    });
}

async fn is_user_admin(db: &sqlx::PgPool, user_id: &str) -> bool {
    crate::db::user_has_role(db, user_id, "super_admin")
        .await
        .unwrap_or(false)
        || crate::db::user_has_role(db, user_id, "admin")
            .await
            .unwrap_or(false)
}

async fn run_third_party_import(
    db: &sqlx::PgPool,
    provider: &str,
    users: Vec<ThirdPartyUserImportItem>,
    dry_run: bool,
    actor: Option<&str>,
) -> ThirdPartyUserImportOutput {
    const MAX_IMPORT_BATCH_SIZE: usize = 10_000;

    let total = users.len();
    let mut results: Vec<ThirdPartyUserImportResultItem> = Vec::with_capacity(users.len());
    let mut created = 0usize;
    let mut updated = 0usize;
    let mut linked = 0usize;
    let mut failed = 0usize;

    if total > MAX_IMPORT_BATCH_SIZE {
        return ThirdPartyUserImportOutput {
            provider: provider.to_string(),
            dry_run,
            summary: ThirdPartyUserImportSummary {
                total,
                created: 0,
                updated: 0,
                linked: 0,
                failed: total,
            },
            results: vec![ThirdPartyUserImportResultItem {
                external_user_id: String::new(),
                user_id: None,
                status: "failed".to_string(),
                error_code: Some(MigrationErrorCode::InvalidInput),
                message: Some(format!(
                    "Batch too large: {} items exceed maximum of {}",
                    total, MAX_IMPORT_BATCH_SIZE
                )),
            }],
        };
    }

    for item in users {
        let external_user_id = item.external_user_id.trim().to_string();
        let username = item.username.trim().to_string();
        let email = item.email.trim().to_string();

        if external_user_id.is_empty() || username.is_empty() || email.is_empty() {
            failed += 1;
            push_failed_result(
                &mut results,
                external_user_id,
                None,
                MigrationErrorCode::InvalidInput,
                "external_user_id/username/email are required".to_string(),
            );
            continue;
        }

        let active = item.active.unwrap_or(true);
        if let Some(password) = item.password.as_deref() {
            if let Err(msg) = validate_password_complexity(password) {
                failed += 1;
                push_failed_result(
                    &mut results,
                    external_user_id,
                    None,
                    MigrationErrorCode::InvalidInput,
                    msg.to_string(),
                );
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
                error_code: None,
                message: Some("validated".to_string()),
            });
            continue;
        }

        let mapped_user_id = match get_mapped_user_id(db, provider, &external_user_id).await {
            Ok(value) => value,
            Err(e) => {
                failed += 1;
                push_failed_result(
                    &mut results,
                    external_user_id,
                    None,
                    MigrationErrorCode::MappingError,
                    format!("failed to query mapping: {e}"),
                );
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
                            let error_string = e.to_string();
                            push_failed_result(
                                &mut results,
                                external_user_id,
                                Some(user.id.clone()),
                                map_item_error_code(&error_string),
                                format!("failed to update mapped user: {error_string}"),
                            );
                            continue;
                        }
                    }
                }
                Ok(None) => {
                    match create_user(db, &username, &email, item.password.as_deref()).await {
                        Ok(new_user) => {
                            if !active {
                                if let Err(e) = set_user_active(db, &new_user.id, false).await {
                                    tracing::warn!(
                                        "import: failed to deactivate newly created user {}: {}",
                                        new_user.id,
                                        e
                                    );
                                }
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
                            let error_string = e.to_string();
                            push_failed_result(
                                &mut results,
                                external_user_id,
                                None,
                                map_item_error_code(&error_string),
                                format!("failed to create remapped user: {error_string}"),
                            );
                            continue;
                        }
                    }
                }
                Err(e) => {
                    failed += 1;
                    push_failed_result(
                        &mut results,
                        external_user_id,
                        None,
                        MigrationErrorCode::InternalError,
                        format!("failed to load mapped user: {e}"),
                    );
                    continue;
                }
            }
        } else {
            match get_user_by_email(db, &email).await {
                Ok(Some(user)) => {
                    linked += 1;
                    if let Err(e) = update_user(
                        db,
                        &user.id,
                        Some(&username),
                        Some(&email),
                        item.password.as_deref(),
                        Some(active),
                    )
                    .await
                    {
                        tracing::warn!("import: failed to update linked user {}: {}", user.id, e);
                    }
                    (user.clone(), "linked".to_string(), Some(user.id.clone()))
                }
                Ok(None) => match get_user_by_username(db, &username).await {
                    Ok(Some(user)) => {
                        linked += 1;
                        if let Err(e) = update_user(
                            db,
                            &user.id,
                            Some(&username),
                            Some(&email),
                            item.password.as_deref(),
                            Some(active),
                        )
                        .await
                        {
                            tracing::warn!(
                                "import: failed to update linked user {}: {}",
                                user.id,
                                e
                            );
                        }
                        (user.clone(), "linked".to_string(), Some(user.id.clone()))
                    }
                    Ok(None) => {
                        match create_user(db, &username, &email, item.password.as_deref()).await {
                            Ok(user) => {
                                if !active {
                                    if let Err(e) = set_user_active(db, &user.id, false).await {
                                        tracing::warn!("import: failed to deactivate newly created user {}: {}", user.id, e);
                                    }
                                }
                                created += 1;
                                (user.clone(), "created".to_string(), Some(user.id.clone()))
                            }
                            Err(e) => {
                                failed += 1;
                                let error_string = e.to_string();
                                push_failed_result(
                                    &mut results,
                                    external_user_id,
                                    None,
                                    map_item_error_code(&error_string),
                                    format!("failed to create user: {error_string}"),
                                );
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        failed += 1;
                        push_failed_result(
                            &mut results,
                            external_user_id,
                            None,
                            MigrationErrorCode::InternalError,
                            format!("failed to lookup user by username: {e}"),
                        );
                        continue;
                    }
                },
                Err(e) => {
                    failed += 1;
                    push_failed_result(
                        &mut results,
                        external_user_id,
                        None,
                        MigrationErrorCode::InternalError,
                        format!("failed to lookup user by email: {e}"),
                    );
                    continue;
                }
            }
        };

        if let Err(e) = upsert_external_user_mapping(
            db,
            provider,
            &external_user_id,
            &resolved_user.id,
            metadata_value.as_ref(),
        )
        .await
        {
            failed += 1;
            push_failed_result(
                &mut results,
                external_user_id,
                Some(resolved_user.id),
                MigrationErrorCode::MappingError,
                format!("failed to upsert external mapping: {e}"),
            );
            continue;
        }

        let mut role_assignment_failed = false;
        if let Some(roles) = item.roles {
            for role_name in roles {
                match get_role_by_name(db, role_name.trim()).await {
                    Ok(Some(role)) => {
                        if let Err(e) = assign_role_to_user(db, &resolved_user.id, &role.id).await {
                            failed += 1;
                            role_assignment_failed = true;
                            push_failed_result(
                                &mut results,
                                external_user_id.clone(),
                                Some(resolved_user.id.clone()),
                                MigrationErrorCode::RoleAssignmentFailed,
                                format!("failed to assign role: {e}"),
                            );
                            break;
                        }
                    }
                    Ok(None) => {
                        failed += 1;
                        role_assignment_failed = true;
                        push_failed_result(
                            &mut results,
                            external_user_id.clone(),
                            Some(resolved_user.id.clone()),
                            MigrationErrorCode::InvalidInput,
                            format!("role not found: {}", role_name.trim()),
                        );
                        break;
                    }
                    Err(e) => {
                        failed += 1;
                        role_assignment_failed = true;
                        push_failed_result(
                            &mut results,
                            external_user_id.clone(),
                            Some(resolved_user.id.clone()),
                            MigrationErrorCode::RoleAssignmentFailed,
                            format!("failed to query role: {e}"),
                        );
                        break;
                    }
                }
            }
        }

        if role_assignment_failed {
            continue;
        }

        results.push(ThirdPartyUserImportResultItem {
            external_user_id,
            user_id: user_id.or(Some(resolved_user.id)),
            status,
            error_code: None,
            message: None,
        });
    }

    let summary = ThirdPartyUserImportSummary {
        total,
        created,
        updated,
        linked,
        failed,
    };

    if let Some(actor_sub) = actor {
        let _ = create_audit_log(
            db,
            "migration.third_party.users.import",
            Some(actor_sub),
            Some(&format!(
                "provider={}, dry_run={}, total={}, created={}, updated={}, linked={}, failed={}",
                provider,
                dry_run,
                summary.total,
                summary.created,
                summary.updated,
                summary.linked,
                summary.failed
            )),
        )
        .await;
    }

    ThirdPartyUserImportOutput {
        provider: provider.to_string(),
        dry_run,
        summary,
        results,
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
            return Err(migration_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                MigrationErrorCode::InternalError,
                "Database not available",
            ));
        }
    };

    if req.users.is_empty() {
        return Err(migration_error_response(
            StatusCode::BAD_REQUEST,
            MigrationErrorCode::InvalidInput,
            "users must not be empty",
        ));
    }

    let provider = req.provider.trim().to_lowercase();
    if provider.is_empty() {
        return Err(migration_error_response(
            StatusCode::BAD_REQUEST,
            MigrationErrorCode::ProviderInvalid,
            "provider must not be empty",
        ));
    }

    let dry_run = req.dry_run.unwrap_or(false);
    let output = run_third_party_import(db, &provider, req.users, dry_run, Some(&claims.sub)).await;

    Ok(Json(json!({
        "success": true,
        "provider": output.provider,
        "dry_run": output.dry_run,
        "summary": output.summary,
        "results": output.results
    })))
}

/// 单用户 JIT 迁移注册（登录时迁移）
pub async fn jit_register_user(
    State(state): State<AppState>,
    Json(req): Json<ThirdPartyJitRegisterRequest>,
) -> ApiResponse {
    let db = match &state.db {
        Some(db) => db,
        None => {
            return Err(migration_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                MigrationErrorCode::InternalError,
                "Database not available",
            ));
        }
    };

    let provider = req.provider.trim().to_lowercase();
    if provider.is_empty() {
        return Err(migration_error_response(
            StatusCode::BAD_REQUEST,
            MigrationErrorCode::ProviderInvalid,
            "provider must not be empty",
        ));
    }

    let output = run_third_party_import(
        db,
        &provider,
        vec![ThirdPartyUserImportItem {
            external_user_id: req.external_user_id,
            username: req.username,
            email: req.email,
            password: req.password,
            active: req.active,
            roles: req.roles,
            metadata: req.metadata,
        }],
        false,
        Some("jit"),
    )
    .await;

    if output.summary.failed > 0 {
        let first = output.results.first();
        let error_code = first
            .and_then(|item| item.error_code.clone())
            .unwrap_or(MigrationErrorCode::InternalError);
        let message = first
            .and_then(|item| item.message.clone())
            .unwrap_or_else(|| "jit migration failed".to_string());
        let status = match error_code {
            MigrationErrorCode::Conflict => StatusCode::CONFLICT,
            MigrationErrorCode::InvalidInput | MigrationErrorCode::ProviderInvalid => {
                StatusCode::BAD_REQUEST
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return Err(migration_error_response(status, error_code, &message));
    }

    let result_item = output.results.first().ok_or_else(|| {
        migration_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            MigrationErrorCode::InternalError,
            "jit migration produced empty result",
        )
    })?;

    let user_id = result_item.user_id.clone().ok_or_else(|| {
        migration_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            MigrationErrorCode::InternalError,
            "jit migration user_id missing",
        )
    })?;

    let user = get_user_by_id(db, &user_id).await.map_err(|e| {
        migration_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            MigrationErrorCode::InternalError,
            &format!("failed to load migrated user: {e}"),
        )
    })?;

    let user = user.ok_or_else(|| {
        migration_error_response(
            StatusCode::NOT_FOUND,
            MigrationErrorCode::InternalError,
            "migrated user not found",
        )
    })?;

    let is_admin = is_user_admin(db, &user.id).await;
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: format!("user:{}", user.username),
        iss: state.config.jwt_issuer.clone(),
        aud: "admin-backend".to_string(),
        scope: if is_admin {
            vec!["read".into(), "write".into(), "admin".into()]
        } else {
            vec!["read".into(), "write".into()]
        },
        role: vec![if is_admin {
            "admin".to_string()
        } else {
            "user".to_string()
        }],
        iat: now,
        exp: now + state.config.token_expiry_seconds,
        jti: crate::utils::generate_jti(),
        token_type: "access".to_string(),
    };

    let access_token = state.jwt_keys.sign_token(&claims).map_err(|_| {
        migration_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            MigrationErrorCode::InternalError,
            "failed to mint access token",
        )
    })?;

    Ok(Json(json!({
        "success": true,
        "provider": provider,
        "migration_status": result_item.status,
        "user_id": user.id,
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": state.config.token_expiry_seconds
    })))
}

/// 启动异步导入任务（批次任务）
pub async fn start_third_party_import_job(
    State(state): State<AppState>,
    claims: Claims,
    Json(req): Json<ThirdPartyUserImportRequest>,
) -> ApiResponse {
    if req.users.is_empty() {
        return Err(migration_error_response(
            StatusCode::BAD_REQUEST,
            MigrationErrorCode::InvalidInput,
            "users must not be empty",
        ));
    }

    let provider = req.provider.trim().to_lowercase();
    if provider.is_empty() {
        return Err(migration_error_response(
            StatusCode::BAD_REQUEST,
            MigrationErrorCode::ProviderInvalid,
            "provider must not be empty",
        ));
    }

    let now = Utc::now().timestamp();
    let job_id = Uuid::new_v4().to_string();
    let dry_run = req.dry_run.unwrap_or(false);
    let users = req.users;
    let total_users = users.len();
    let actor = claims.sub.clone();

    {
        let mut jobs = state.migration_jobs.write().await;
        jobs.insert(
            job_id.clone(),
            MigrationBatchJob {
                job_id: job_id.clone(),
                provider: provider.clone(),
                dry_run,
                total_users,
                actor: actor.clone(),
                status: MigrationJobStatus::Pending,
                created_at: now,
                updated_at: now,
                finished_at: None,
                error_code: None,
                error_message: None,
                result: None,
            },
        );
    }

    let state_for_task = state.clone();
    let job_id_for_task = job_id.clone();
    let provider_for_task = provider.clone();
    tokio::spawn(async move {
        {
            let mut jobs = state_for_task.migration_jobs.write().await;
            if let Some(job) = jobs.get_mut(&job_id_for_task) {
                job.status = MigrationJobStatus::Running;
                job.updated_at = Utc::now().timestamp();
            }
        }

        let db = match &state_for_task.db {
            Some(db) => db,
            None => {
                let mut jobs = state_for_task.migration_jobs.write().await;
                if let Some(job) = jobs.get_mut(&job_id_for_task) {
                    job.status = MigrationJobStatus::Failed;
                    job.updated_at = Utc::now().timestamp();
                    job.finished_at = Some(Utc::now().timestamp());
                    job.error_code = Some(MigrationErrorCode::InternalError);
                    job.error_message = Some("Database not available".to_string());
                }
                return;
            }
        };

        let output =
            run_third_party_import(db, &provider_for_task, users, dry_run, Some(&actor)).await;

        let mut jobs = state_for_task.migration_jobs.write().await;
        if let Some(job) = jobs.get_mut(&job_id_for_task) {
            job.status = MigrationJobStatus::Completed;
            job.updated_at = Utc::now().timestamp();
            job.finished_at = Some(Utc::now().timestamp());
            job.result = Some(output);
        }
    });

    Ok(Json(json!({
        "success": true,
        "job_id": job_id,
        "status": "pending",
        "provider": provider,
        "total_users": total_users,
        "dry_run": dry_run
    })))
}

/// 查询异步导入任务状态
pub async fn get_third_party_import_job_status(
    State(state): State<AppState>,
    axum::extract::Path(job_id): axum::extract::Path<String>,
) -> ApiResponse {
    let jobs = state.migration_jobs.read().await;
    let job = jobs.get(&job_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error_code": MigrationErrorCode::NotFound,
                "error": "job not found"
            })),
        )
    })?;

    Ok(Json(json!({
        "success": true,
        "job": job
    })))
}

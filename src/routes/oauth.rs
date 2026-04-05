use anyhow::Result;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Json, Redirect},
    routing::{delete, get, post, put},
    Router,
};
use serde_json::json;
use uuid::Uuid;

use crate::{
    db::*,
    models::*,
    state::AppState,
    utils::{require_db, ApiResponse},
};

/// 创建OAuth路由
pub fn oauth_admin_routes() -> Router<AppState> {
    Router::new()
        // OAuth提供商管理路由 (管理员)
        .route("/providers", get(get_oauth_providers))
        .route("/providers", post(create_oauth_provider_handler))
        .route("/providers/{provider_id}", get(get_oauth_provider))
        .route(
            "/providers/{provider_id}",
            put(update_oauth_provider_handler),
        )
        .route(
            "/providers/{provider_id}",
            delete(delete_oauth_provider_handler),
        )
        // 用户OAuth账户管理路由
        .route("/accounts", get(get_user_oauth_accounts_handler))
        .route("/link", post(link_oauth_account_handler))
        .route("/unlink/{provider}", delete(unlink_oauth_account_handler))
}

/// OAuth公开路由（无需鉴权）
pub fn oauth_public_routes() -> Router<AppState> {
    Router::new()
        .route("/login/{provider}", get(oauth_login))
        .route("/callback/{provider}", get(oauth_callback))
}

/// 获取所有OAuth提供商
async fn get_oauth_providers(State(state): State<AppState>) -> ApiResponse {
    let db = require_db(&state)?;

    match get_all_oauth_providers(db).await {
        Ok(providers) => Ok(Json(json!({
            "success": true,
            "data": providers
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to get OAuth providers: {}", e)
            })),
        )),
    }
}

/// 创建OAuth提供商
async fn create_oauth_provider_handler(
    State(state): State<AppState>,
    Json(req): Json<CreateOAuthProviderRequest>,
) -> ApiResponse {
    let db = require_db(&state)?;

    match create_oauth_provider(
        db,
        &req.name,
        &req.client_id,
        &req.client_secret,
        &req.authorization_url,
        &req.token_url,
        &req.user_info_url,
        &req.scope,
        &req.redirect_url,
    )
    .await
    {
        Ok(provider) => Ok(Json(json!({
            "success": true,
            "data": provider
        }))),
        Err(e) => {
            if e.to_string().contains("duplicate key") {
                Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "success": false,
                        "error": "OAuth provider with this name already exists"
                    })),
                ))
            } else {
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "success": false,
                        "error": format!("Failed to create OAuth provider: {}", e)
                    })),
                ))
            }
        }
    }
}

/// 获取单个OAuth提供商
async fn get_oauth_provider(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
) -> ApiResponse {
    let db = require_db(&state)?;

    match get_oauth_provider_by_id(db, &provider_id).await {
        Ok(Some(provider)) => Ok(Json(json!({
            "success": true,
            "data": provider
        }))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "OAuth provider not found"
            })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to get OAuth provider: {}", e)
            })),
        )),
    }
}

/// 更新OAuth提供商
async fn update_oauth_provider_handler(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
    Json(req): Json<UpdateOAuthProviderRequest>,
) -> ApiResponse {
    let db = require_db(&state)?;

    match update_oauth_provider(
        db,
        &provider_id,
        req.name.as_deref(),
        req.client_id.as_deref(),
        req.client_secret.as_deref(),
        req.authorization_url.as_deref(),
        req.token_url.as_deref(),
        req.user_info_url.as_deref(),
        req.scope.as_deref(),
        req.redirect_url.as_deref(),
        req.active,
    )
    .await
    {
        Ok(Some(provider)) => Ok(Json(json!({
            "success": true,
            "data": provider
        }))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "OAuth provider not found"
            })),
        )),
        Err(e) => {
            if e.to_string().contains("duplicate key") {
                Err((
                    StatusCode::CONFLICT,
                    Json(json!({
                        "success": false,
                        "error": "OAuth provider with this name already exists"
                    })),
                ))
            } else {
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "success": false,
                        "error": format!("Failed to update OAuth provider: {}", e)
                    })),
                ))
            }
        }
    }
}

/// 删除OAuth提供商
async fn delete_oauth_provider_handler(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
) -> ApiResponse {
    let db = require_db(&state)?;

    match delete_oauth_provider(db, &provider_id).await {
        Ok(true) => Ok(Json(json!({
            "success": true,
            "message": "OAuth provider deleted successfully"
        }))),
        Ok(false) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "OAuth provider not found"
            })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to delete OAuth provider: {}", e)
            })),
        )),
    }
}

/// 发起OAuth登录
async fn oauth_login(
    State(state): State<AppState>,
    Path(provider_name): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Redirect, (StatusCode, Json<serde_json::Value>)> {
    let db = require_db(&state)?;
    // 获取OAuth提供商配置
    let provider = match get_oauth_provider_by_name(db, &provider_name).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({
                    "success": false,
                    "error": "OAuth provider not found"
                })),
            ));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Database error: {}", e)
                })),
            ));
        }
    };

    // 生成state参数用于CSRF保护
    let oauth_state = Uuid::new_v4().to_string();
    let state_exp = chrono::Utc::now().timestamp() + 600;
    state
        .store_oauth_state(oauth_state.clone(), state_exp)
        .await;

    // 构建授权URL
    let mut auth_url = format!(
        "{}?client_id={}&redirect_uri={}&scope={}&response_type=code&state={}",
        provider.authorization_url,
        provider.client_id,
        urlencoding::encode(&provider.redirect_url),
        urlencoding::encode(&provider.scope),
        oauth_state
    );

    // 添加额外的查询参数
    for (key, value) in params {
        auth_url.push_str(&format!("&{}={}", key, urlencoding::encode(&value)));
    }

    // 重定向到OAuth提供商
    Ok(Redirect::to(&auth_url))
}

/// OAuth回调处理
async fn oauth_callback(
    State(state): State<AppState>,
    Path(provider_name): Path<String>,
    Query(query): Query<OAuthAuthorizeQuery>,
) -> Result<Json<OAuthLoginResponse>, (StatusCode, Json<serde_json::Value>)> {
    let callback_state = match query.state.as_deref() {
        Some(value) => value,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "error": "Missing OAuth state",
                })),
            ));
        }
    };

    if !state.consume_oauth_state(callback_state).await {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "Invalid or expired OAuth state",
            })),
        ));
    }

    let db = require_db(&state)?;
    // 获取OAuth提供商配置
    let provider = match get_oauth_provider_by_name(db, &provider_name).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({
                    "success": false,
                    "error": "OAuth provider not found"
                })),
            ));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Database error: {}", e)
                })),
            ));
        }
    };

    // 交换授权码获取访问令牌
    let token_response = match exchange_code_for_token(&provider, &query.code).await {
        Ok(token) => token,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "error": format!("Failed to exchange code for token: {}", e)
                })),
            ));
        }
    };

    // 获取用户信息
    let user_info = match get_oauth_user_info(&provider, &token_response.access_token).await {
        Ok(info) => info,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "error": format!("Failed to get user info: {}", e)
                })),
            ));
        }
    };

    // 检查是否已有关联账户
    let existing_account = find_oauth_account_by_provider_user_id(db, &provider.id, &user_info.id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Database error: {}", e)
                })),
            )
        })?;

    let user_id = if let Some(account) = existing_account {
        // 更新token信息
        update_oauth_account_tokens(
            db,
            &account.id,
            Some(&token_response.access_token),
            token_response.refresh_token.as_deref(),
            token_response.expires_in.map(|expires| {
                chrono::Local::now().naive_utc() + chrono::Duration::seconds(expires)
            }),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Failed to update tokens: {}", e)
                })),
            )
        })?;

        account.user_id
    } else {
        // 创建新用户
        let new_user_id = Uuid::new_v4().to_string();
        let username = user_info
            .login
            .clone()
            .unwrap_or_else(|| format!("user_{}", Uuid::new_v4().simple()));
        let email = user_info
            .email
            .clone()
            .unwrap_or_else(|| format!("{}@oauth.local", username));

        // 创建用户记录
        crate::db::create_user(db, &new_user_id, &username, Some(&email))
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "success": false,
                        "error": format!("Failed to create user: {}", e)
                    })),
                )
            })?;

        // 关联OAuth账户
        link_oauth_account(
            db,
            &new_user_id,
            &provider.id,
            &user_info.id,
            user_info.login.as_deref(),
            user_info.email.as_deref(),
            Some(&token_response.access_token),
            token_response.refresh_token.as_deref(),
            token_response.expires_in.map(|expires| {
                chrono::Local::now().naive_utc() + chrono::Duration::seconds(expires)
            }),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Failed to link OAuth account: {}", e)
                })),
            )
        })?;

        new_user_id
    };

    // 生成JWT token
    let token_expires_in = 3600; // 1小时
    let now = chrono::Utc::now().timestamp();
    let access_claims = crate::models::Claims {
        sub: user_id.clone(),
        iss: "keylo".to_string(),
        aud: "oauth-client".to_string(),
        scope: vec!["read".into(), "write".into()],
        iat: now,
        exp: now + token_expires_in,
        jti: uuid::Uuid::new_v4().to_string(),
        token_type: "access".to_string(),
    };

    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &access_claims,
        &state.jwt_keys.encoding,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to generate token: {}", e)
            })),
        )
    })?;

    // 获取用户的关联提供商列表
    let oauth_accounts = get_user_oauth_accounts(db, &user_id)
        .await
        .unwrap_or_default();
    let linked_providers = oauth_accounts
        .into_iter()
        .map(|acc| acc.provider_id)
        .collect();

    let response = OAuthLoginResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: token_expires_in,
        refresh_token: token_response.refresh_token,
        user: OAuthUserResponse {
            id: user_id,
            username: user_info.login,
            email: user_info.email,
            linked_providers,
        },
    };

    Ok(Json(response))
}

/// 获取用户的OAuth账户
async fn get_user_oauth_accounts_handler(
    claims: crate::models::Claims,
    State(state): State<AppState>,
) -> ApiResponse {
    let db = require_db(&state)?;
    let user_id = claims.sub;

    match get_user_oauth_accounts(db, &user_id).await {
        Ok(accounts) => Ok(Json(json!({
            "success": true,
            "data": accounts
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to get OAuth accounts: {}", e)
            })),
        )),
    }
}

/// 关联OAuth账户
async fn link_oauth_account_handler(
    claims: crate::models::Claims,
    State(state): State<AppState>,
    Json(req): Json<LinkOAuthAccountRequest>,
) -> ApiResponse {
    let user_id = claims.sub;

    // 获取OAuth提供商
    let db = require_db(&state)?;
    let provider = match get_oauth_provider_by_name(db, &req.provider).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({
                    "success": false,
                    "error": "OAuth provider not found"
                })),
            ));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Database error: {}", e)
                })),
            ));
        }
    };

    // 交换授权码获取访问令牌
    let db = require_db(&state)?;
    let token_response = match exchange_code_for_token(&provider, &req.code).await {
        Ok(token) => token,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "error": format!("Failed to exchange code for token: {}", e)
                })),
            ));
        }
    };

    // 获取用户信息
    let user_info = match get_oauth_user_info(&provider, &token_response.access_token).await {
        Ok(info) => info,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "error": format!("Failed to get user info: {}", e)
                })),
            ));
        }
    };

    // 检查是否已被其他用户关联
    if (find_oauth_account_by_provider_user_id(db, &provider.id, &user_info.id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Database error: {}", e)
                })),
            )
        })?)
    .is_some()
    {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({
                "success": false,
                "error": "OAuth account already linked to another user"
            })),
        ));
    }

    // 关联OAuth账户
    match link_oauth_account(
        db,
        &user_id,
        &provider.id,
        &user_info.id,
        user_info.login.as_deref(),
        user_info.email.as_deref(),
        Some(&token_response.access_token),
        token_response.refresh_token.as_deref(),
        token_response
            .expires_in
            .map(|expires| chrono::Local::now().naive_utc() + chrono::Duration::seconds(expires)),
    )
    .await
    {
        Ok(account) => Ok(Json(json!({
            "success": true,
            "data": account
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to link OAuth account: {}", e)
            })),
        )),
    }
}

/// 取消关联OAuth账户
async fn unlink_oauth_account_handler(
    claims: crate::models::Claims,
    State(state): State<AppState>,
    Path(provider_name): Path<String>,
) -> ApiResponse {
    let user_id = claims.sub;

    // 获取提供商ID
    let db = require_db(&state)?;
    let provider = match get_oauth_provider_by_name(db, &provider_name).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({
                    "success": false,
                    "error": "OAuth provider not found"
                })),
            ));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": format!("Database error: {}", e)
                })),
            ));
        }
    };

    match unlink_oauth_account(db, &user_id, &provider.id).await {
        Ok(true) => Ok(Json(json!({
            "success": true,
            "message": "OAuth account unlinked successfully"
        }))),
        Ok(false) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "OAuth account not found"
            })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": format!("Failed to unlink OAuth account: {}", e)
            })),
        )),
    }
}

/// 交换授权码获取访问令牌
async fn exchange_code_for_token(
    provider: &OAuthProvider,
    code: &str,
) -> Result<OAuthTokenResponse, anyhow::Error> {
    let client = reqwest::Client::new();
    let params = [
        ("client_id", &provider.client_id),
        ("client_secret", &provider.client_secret),
        ("code", &code.to_string()),
        ("grant_type", &"authorization_code".to_string()),
        ("redirect_uri", &provider.redirect_url),
    ];

    let response = client
        .post(&provider.token_url)
        .form(&params)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Token exchange failed: {}",
            response.status()
        ));
    }

    let token_response: OAuthTokenResponse = response.json().await?;
    Ok(token_response)
}

/// 获取OAuth用户信息
async fn get_oauth_user_info(
    provider: &OAuthProvider,
    access_token: &str,
) -> Result<OAuthUserInfo, anyhow::Error> {
    let client = reqwest::Client::new();
    let response = client
        .get(&provider.user_info_url)
        .header("Authorization", format!("Bearer {}", access_token))
        .header("User-Agent", "Keylo-OAuth/1.0")
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to get user info: {}",
            response.status()
        ));
    }

    let user_info: OAuthUserInfo = response.json().await?;
    Ok(user_info)
}

use crate::db::user::get_user_by_username;
use crate::errors::AuthError;
use crate::models::{
    AuthBody, AuthPayload, BlacklistTokenRequest, Claims, MeResponse, RefreshTokenRequest,
};
use crate::state::AppState;
use crate::utils;
use axum::extract::State;
use axum::Json;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use bcrypt::verify;
use chrono::Utc;
use jsonwebtoken::{encode, Header};
use serde_json::json;

pub async fn auth_token(
    State(state): State<AppState>,
    Json(payload): Json<AuthPayload>,
) -> Result<Json<AuthBody>, AuthError> {
    // Check if the user sent the credentials
    if payload.client_id.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    let db = match &state.db {
        Some(db) => db,
        None => return Err(AuthError::DatabaseError("Database not available".to_string())),
    };

    // First try to authenticate as a user
    let user_result = get_user_by_username(db, &payload.client_id).await;
    let (is_user_valid, _user_id) = match user_result {
        Ok(Some(user)) => {
            // Verify password
            if let Some(ref password_hash) = user.password_hash {
                let result = verify(&payload.client_secret, password_hash)
                    .map_err(|_| AuthError::WrongCredentials)?;
                println!("Password verification result: {}", result);
                (result, Some(user.id))
            } else {
                println!("User has no password hash");
                (false, None)
            }
        }
        Ok(None) => {
            println!("User not found: {}", payload.client_id);
            (false, None)
        }
        Err(e) => {
            println!("Database error getting user: {:?}", e);
            return Err(AuthError::DatabaseError("Failed to get user".to_string()));
        }
    };

    let subject_prefix = if is_user_valid {
        "user"
    } else {
        // If user auth failed, try client auth
        if !state.validate_client(&payload.client_id, &payload.client_secret) {
            return Err(AuthError::WrongCredentials);
        }
        "client"
    };

    let now = Utc::now().timestamp();

    // Create access token claims
    let access_claims = Claims {
        sub: format!("{}:{}", subject_prefix, payload.client_id),
        iss: "keylo".to_string(),
        aud: "admin-backend".to_string(),
        scope: vec!["read".into(), "write".into()],
        iat: now,
        exp: now + state.config.token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "access".to_string(),
    };

    // Create refresh token claims
    let refresh_claims = Claims {
        sub: format!("{}:{}", subject_prefix, payload.client_id),
        iss: "keylo".to_string(),
        aud: "admin-backend".to_string(),
        scope: vec!["refresh".into()],
        iat: now,
        exp: now + state.config.refresh_token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "refresh".to_string(),
    };

    // Create the authorization tokens
    let access_token = encode(&Header::default(), &access_claims, &state.jwt_keys.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    let refresh_token = encode(
        &Header::default(),
        &refresh_claims,
        &state.jwt_keys.encoding,
    )
    .map_err(|_| AuthError::TokenCreation)?;

    // Store refresh token in database (only for client auth)
    if let Some(db) = &state.db {
        if !is_user_valid {
            crate::db::create_refresh_token(
                db,
                &refresh_claims.jti,
                &payload.client_id,
                &refresh_token,
                refresh_claims.exp,
            )
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to create refresh token".to_string()))?;
        }
    } else {
        return Err(AuthError::DatabaseError(
            "Database not available".to_string(),
        ));
    }

    // Send the authorized tokens
    Ok(Json(AuthBody::new(
        access_token,
        refresh_token,
        state.config.token_expiry_seconds,
    )))
}

pub async fn auth_blacklist_token(
    State(state): State<AppState>,
    claims: Claims,
    Json(payload): Json<BlacklistTokenRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    // 只有管理员可以执行此操作
    if !claims.scope.contains(&"admin".to_string()) {
        return Err(AuthError::Forbidden);
    }

    if let Some(db) = &state.db {
        crate::db::blacklist_token(
            db,
            &payload.token,
            payload.reason.as_deref(),
            payload
                .expires_at
                .unwrap_or_else(|| Utc::now().timestamp() + 3600), // 默认1小时
        )
        .await
        .map_err(|_| AuthError::DatabaseError("Failed to blacklist token".to_string()))?;
    } else {
        return Err(AuthError::DatabaseError(
            "Database not available".to_string(),
        ));
    }

    Ok(Json(json!({
        "message": "Token blacklisted successfully",
        "token": payload.token,
    })))
}

pub async fn auth_get_blacklisted_tokens(
    State(state): State<AppState>,
    claims: Claims,
) -> Result<Json<serde_json::Value>, AuthError> {
    // 只有管理员可以执行此操作
    if !claims.scope.contains(&"admin".to_string()) {
        return Err(AuthError::Forbidden);
    }

    if let Some(db) = &state.db {
        let tokens = crate::db::get_active_blacklisted_tokens(db)
            .await
            .map_err(|_| {
                AuthError::DatabaseError("Failed to get blacklisted tokens".to_string())
            })?;

        Ok(Json(json!({
            "blacklisted_tokens": tokens.into_iter().map(|(token, reason, expires_at)| {
                json!({
                    "token": token,
                    "reason": reason,
                    "expires_at": expires_at,
                })
            }).collect::<Vec<_>>()
        })))
    } else {
        Err(AuthError::DatabaseError(
            "Database not available".to_string(),
        ))
    }
}

pub async fn auth_me(claims: Claims) -> Result<Json<MeResponse>, AuthError> {
    Ok(Json(MeResponse {
        sub: claims.sub,
        scope: claims.scope,
        aud: claims.aud,
        exp: claims.exp,
        iss: claims.iss,
        jti: claims.jti,
    }))
}

pub async fn auth_refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<AuthBody>, AuthError> {
    // Check if refresh token exists and is not revoked
    let (token_id, client_id) = if let Some(db) = &state.db {
        match crate::db::validate_refresh_token(db, &payload.refresh_token).await {
            Ok(Some((id, client_id))) => (id, client_id),
            _ => return Err(AuthError::InvalidToken),
        }
    } else {
        return Err(AuthError::DatabaseError(
            "Database not available".to_string(),
        ));
    };

    let now = Utc::now().timestamp();

    // Create new access token claims
    let access_claims = Claims {
        sub: format!("client:{}", client_id),
        iss: "keylo".to_string(),
        aud: "admin-backend".to_string(),
        scope: vec!["read".into(), "write".into()],
        iat: now,
        exp: now + state.config.token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "access".to_string(),
    };

    // Create new refresh token claims
    let new_refresh_claims = Claims {
        sub: format!("client:{}", client_id),
        iss: "keylo".to_string(),
        aud: "admin-backend".to_string(),
        scope: vec!["refresh".into()],
        iat: now,
        exp: now + state.config.refresh_token_expiry_seconds,
        jti: utils::generate_jti(),
        token_type: "refresh".to_string(),
    };

    // Create new tokens
    let access_token = encode(&Header::default(), &access_claims, &state.jwt_keys.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    let new_refresh_token = encode(
        &Header::default(),
        &new_refresh_claims,
        &state.jwt_keys.encoding,
    )
    .map_err(|_| AuthError::TokenCreation)?;

    // Revoke old refresh token
    if let Some(db) = &state.db {
        crate::db::revoke_refresh_token(db, &token_id)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to revoke refresh token".to_string()))?;
    }

    // Store new refresh token
    if let Some(db) = &state.db {
        crate::db::create_refresh_token(
            db,
            &new_refresh_claims.jti,
            &client_id,
            &new_refresh_token,
            new_refresh_claims.exp,
        )
        .await
        .map_err(|_| AuthError::DatabaseError("Failed to create refresh token".to_string()))?;
    }

    Ok(Json(AuthBody::new(
        access_token,
        new_refresh_token,
        state.config.token_expiry_seconds,
    )))
}

pub async fn auth_logout(
    State(state): State<AppState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    claims: Claims,
) -> Result<Json<serde_json::Value>, AuthError> {
    // 将当前access token加入黑名单
    if let Some(db) = &state.db {
        let token = auth.token();
        crate::db::blacklist_token(db, token, Some("User logout"), claims.exp)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to blacklist token".to_string()))?;
    }

    tracing::info!("User {} logged out", claims.sub);

    Ok(Json(json!({
        "message": "Successfully logged out",
        "sub": claims.sub,
    })))
}

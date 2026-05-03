use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// OAuth提供商模型
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OAuthProvider {
    pub id: String,
    pub name: String,
    pub client_id: String,
    #[serde(skip_serializing)]
    pub client_secret: String,
    pub authorization_url: String,
    pub token_url: String,
    pub user_info_url: String,
    pub scope: String,
    pub redirect_url: String,
    pub active: bool,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

/// 创建OAuth提供商的请求
#[derive(Debug, Deserialize)]
pub struct CreateOAuthProviderRequest {
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub authorization_url: String,
    pub token_url: String,
    pub user_info_url: String,
    pub scope: String,
    pub redirect_url: String,
}

/// 更新OAuth提供商的请求
#[derive(Debug, Deserialize)]
pub struct UpdateOAuthProviderRequest {
    pub name: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub user_info_url: Option<String>,
    pub scope: Option<String>,
    pub redirect_url: Option<String>,
    pub active: Option<bool>,
}

/// 用户OAuth账户关联
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserOAuthAccount {
    pub id: String,
    pub user_id: String,
    pub provider_id: String,
    pub provider_user_id: String,
    pub provider_username: Option<String>,
    pub provider_email: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_expires_at: Option<chrono::NaiveDateTime>,
    pub linked_at: chrono::NaiveDateTime,
    pub last_login_at: Option<chrono::NaiveDateTime>,
}

/// OAuth用户信息（从提供商获取）
#[derive(Debug, Deserialize)]
pub struct OAuthUserInfo {
    pub id: String,
    pub login: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

/// OAuth token响应
#[derive(Debug, Deserialize)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub token_type: Option<String>,
    pub scope: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
}

/// OAuth授权URL查询参数
#[derive(Debug, Deserialize)]
pub struct OAuthAuthorizeQuery {
    pub code: String,
    pub state: Option<String>,
}

/// 关联OAuth账户的请求
#[derive(Debug, Deserialize)]
pub struct LinkOAuthAccountRequest {
    pub provider: String,
    pub code: String,
    pub state: Option<String>,
}

/// OAuth登录响应
#[derive(Debug, Serialize)]
pub struct OAuthLoginResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub user: OAuthUserResponse,
}

/// OAuth用户响应
#[derive(Debug, Serialize)]
pub struct OAuthUserResponse {
    pub id: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub linked_providers: Vec<String>,
}

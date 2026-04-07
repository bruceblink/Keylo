use serde::{Deserialize, Serialize};

/// 服务间鉴权的 JWT Claims（sub 格式为 "service:<service_id>"）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceClaims {
    /// Subject：服务身份，格式 "service:<service_id>"
    pub sub: String,

    /// Issuer：签发方
    pub iss: String,

    /// Audience：目标服务（具体服务 ID 或 "*" 表示通配）
    pub aud: String,

    /// Scope：授权给该服务的权限集合
    pub scope: Vec<String>,

    /// Token 类型固定为 "service_access"
    pub token_type: String,

    /// 过期时间（unix timestamp）
    pub exp: i64,

    /// 签发时间（unix timestamp）
    pub iat: i64,

    /// JWT ID（用于审计与吊销）
    pub jti: String,
}

/// 获取服务 Token 的请求体（Client Credentials Flow）
#[derive(Debug, Deserialize)]
pub struct ServiceTokenRequest {
    /// 服务 ID
    pub service_id: String,
    /// 服务密钥
    pub service_secret: String,
    /// 可选：请求的目标 audience（必须在 allowed_audiences 范围内）
    pub audience: Option<String>,
    /// 可选：请求的 scope 子集（必须在 allowed_scopes 范围内）
    pub scope: Option<String>,
}

/// 服务 Token 响应
#[derive(Debug, Serialize)]
pub struct ServiceTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
}

impl ServiceTokenResponse {
    pub fn new(access_token: String, expires_in: i64, scopes: &[String]) -> Self {
        Self {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in,
            scope: scopes.join(" "),
        }
    }
}

/// Token 内省请求
#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
}

/// Token 内省响应（遵循 RFC 7662）
#[derive(Debug, Serialize)]
pub struct IntrospectResponse {
    /// Token 是否有效
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
}

impl IntrospectResponse {
    pub fn inactive() -> Self {
        Self {
            active: false,
            sub: None,
            scope: None,
            aud: None,
            exp: None,
            iat: None,
            jti: None,
            token_type: None,
        }
    }

    pub fn from_claims(claims: &ServiceClaims) -> Self {
        Self {
            active: true,
            sub: Some(claims.sub.clone()),
            scope: Some(claims.scope.join(" ")),
            aud: Some(claims.aud.clone()),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            jti: Some(claims.jti.clone()),
            token_type: Some(claims.token_type.clone()),
        }
    }
}

/// 注册新服务的请求（管理接口）
#[derive(Debug, Deserialize)]
pub struct RegisterServiceRequest {
    pub service_id: String,
    pub service_secret: String,
    pub name: String,
    pub description: Option<String>,
    /// 允许该服务申请的 scope 列表
    pub allowed_scopes: Vec<String>,
    /// 允许该服务访问的目标 audience 列表（"*" 表示不限）
    pub allowed_audiences: Vec<String>,
}

/// 更新服务配置的请求（管理接口）
#[derive(Debug, Deserialize)]
pub struct UpdateServiceRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub allowed_scopes: Option<Vec<String>>,
    pub allowed_audiences: Option<Vec<String>>,
    pub active: Option<bool>,
}

/// 服务信息（管理接口响应）
#[derive(Debug, Serialize)]
pub struct ServiceInfo {
    pub service_id: String,
    pub name: String,
    pub description: Option<String>,
    pub allowed_scopes: Vec<String>,
    pub allowed_audiences: Vec<String>,
    pub active: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

/// 轮换服务密钥请求
#[derive(Debug, Deserialize)]
pub struct RotateServiceSecretRequest {
    pub new_secret: Option<String>,
}

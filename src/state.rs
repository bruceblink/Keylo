use std::collections::HashMap;
use std::sync::Arc;
use crate::models::Keys;

#[derive(Clone)]
pub struct AppState {
    /// JWT 签名和验证 key
    pub jwt_keys: Keys,

    /// 客户端 ID -> client_secret 的映射
    pub clients: Arc<HashMap<String, String>>,

    /// 可选：受信任的 JWT audience 白名单
    pub audiences: Arc<Vec<String>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        // 从环境变量读取 JWT secret
        let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "my-jwt-secret".to_string());

        // 默认客户端，可以替换成从配置文件或数据库加载
        let mut clients = HashMap::new();
        clients.insert("web".into(), "web-secret".into());
        clients.insert("cli".into(), "cli-secret".into());

        // 默认允许的 audience
        let audiences = vec!["admin-backend".into(), "crawler".into()];

        Self {
            jwt_keys: Keys::new(jwt_secret.as_bytes()),
            clients: Arc::new(clients),
            audiences: Arc::new(audiences),
        }
    }

    /// 校验 client_id + secret 是否存在
    pub fn validate_client(&self, client_id: &str, client_secret: &str) -> bool {
        self.clients
            .get(client_id)
            .is_some_and(|secret| secret == client_secret)
    }

    /// 获取动态的允许 audience
    pub fn allowed_audiences(&self) -> Vec<&str> {
        self.audiences.iter().map(|s| s.as_str()).collect()
    }
}
